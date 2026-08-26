// shared.rs
//! Shared utilities for the Provable Fairness System
//!
//! 1. **Verifiability**: Anyone must be able to re-run the selection
//!    algorithm with the same inputs and get the same winners.
//!
//! 2. **Trust Minimization**: The fairness mechanism should not
//!    require trust in any party.
//!
//! 3. **Auditability**: Security researchers must be able to review
//!    the algorithm for biases or vulnerabilities.
//!
//! 4. **Deterministic**: All functions are pure and deterministic,
//!    making them perfect for open source verification.

use solana_keccak_hasher;

// CONSTANTS

/// Maximum number of winners to display in the reveal event.
/// This is a display limit, not a selection limit.
pub const MAX_DISPLAYED_WINNERS: usize = 6;

/// Maximum participants allowed in a single giveaway.
pub const MAX_PARTICIPANTS: u64 = 100_000;

/// Maximum winners allowed in a single giveaway.
pub const MAX_WINNERS: u64 = 10_000;

/// Number of slots to wait between commit and reveal.
/// ~60 seconds on Solana mainnet (400ms per slot).
pub const REVEAL_DELAY_SLOTS: u64 = 150;

/// Maximum slots after commit that reveal is still valid.
pub const MAX_REVEAL_WINDOW: u64 = 450;

// FISHER-YATES WINNER SELECTION

/// Convert a winner count to a display count (capped at MAX_DISPLAYED_WINNERS).
///
/// # Example
/// ```
/// use provable_fairness_shared::display_count;
///
/// assert_eq!(display_count(0), 0);
/// assert_eq!(display_count(3), 3);
/// assert_eq!(display_count(10), 6); // Capped at 6
/// ```
pub fn display_count(winner_count: u64) -> usize {
    core::cmp::min(winner_count as usize, MAX_DISPLAYED_WINNERS)
}

/// Find a slot hash in the slot hashes sysvar data.
///
/// The slot hashes sysvar stores recent slot hashes in a circular buffer.
/// This function searches for a specific slot and returns its hash.
///
/// # Arguments
/// * `data` - Raw slot hashes sysvar data
/// * `target_slot` - The slot to find
///
/// # Returns
/// * `Some([u8; 32])` - The hash of the target slot
/// * `None` - Slot not found (may have expired)
///
/// # Example
/// ```
/// use provable_fairness_shared::find_slot_hash;
/// use solana_sdk::sysvar::slot_hashes::SlotHashes;
/// use solana_sdk::hash::Hash;
///
/// let mut slot_hashes = SlotHashes::default();
/// let target_slot = 100;
/// let target_hash = Hash::new_unique();
/// slot_hashes.add(target_slot, target_hash);
///
/// let data = bincode::serialize(&slot_hashes).unwrap();
/// let found = find_slot_hash(&data, target_slot);
/// assert_eq!(found.unwrap(), target_hash.to_bytes());
/// ```
pub fn find_slot_hash(data: &[u8], target_slot: u64) -> Option<[u8; 32]> {
    const HEADER_SIZE: usize = 8;
    const ENTRY_SIZE: usize = 40;

    if data.len() < HEADER_SIZE {
        return None;
    }

    let len = u64::from_le_bytes(data[0..8].try_into().ok()?) as usize;

    for i in 0..len {
        let offset = HEADER_SIZE + i * ENTRY_SIZE;
        if offset + ENTRY_SIZE > data.len() {
            break;
        }

        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        if slot == target_slot {
            let hash: [u8; 32] = data[offset + 8..offset + 40].try_into().ok()?;
            return Some(hash);
        }
    }

    None
}

/// Derive randomness from a slot hash and participant root.
///
/// The randomness is the Keccak-256 hash of the concatenation of:
/// `slot_hash || participant_root`
///
/// This ensures that the randomness is:
/// 1. **Unpredictable**: Slot hash is unknown until after commit
/// 2. **Tied to participants**: Can't be reused across different giveaways
/// 3. **Deterministic**: Anyone can verify the derivation
///
/// # Security Properties
/// - The slot hash is a cryptographic hash from the Solana blockchain
/// - Keccak-256 is a cryptographically secure hash function
/// - The combination binds the randomness to the specific participant list
///
/// # Example
/// ```
/// use provable_fairness_shared::derive_randomness;
///
/// let slot_hash = [1u8; 32];
/// let participant_root = [2u8; 32];
///
/// let randomness = derive_randomness(&slot_hash, &participant_root);
/// // Anyone can re-derive this with the same inputs
/// ```
pub fn derive_randomness(target_hash: &[u8; 32], participant_root: &[u8; 32]) -> [u8; 32] {
    let mut combined_seed = [0u8; 64];
    combined_seed[..32].copy_from_slice(target_hash);
    combined_seed[32..].copy_from_slice(participant_root);
    solana_keccak_hasher::hash(&combined_seed).to_bytes()
}

/// Helper for the Fisher-Yates algorithm: get a value from overrides if present.
///
/// This is an internal function used by `select_winner_indices` to handle
/// the Fisher-Yates shuffle in a deterministic way.
fn virtual_get(overrides: &[(u64, u64)], i: u64) -> u64 {
    for &(k, v) in overrides.iter().rev() {
        if k == i {
            return v;
        }
    }
    i
}

/// Select winner indices using the Fisher-Yates algorithm with a deterministic
/// random seed.
///
/// This produces a random permutation of indices from 0 to `participant_count - 1`,
/// then returns the first `winner_count` indices.
///
/// # Algorithm
/// 1. Start with a list of indices `[0, 1, 2, ..., participant_count - 1]`
/// 2. For each position `i` from 0 to `winner_count - 1`:
///    a. Generate a random offset using the deterministic seed
///    b. Swap the element at position `i` with the element at position `i + offset`
///    c. The element at position `i` is now selected
/// 3. Return the first `winner_count` elements
///
/// # Deterministic Properties
/// - Given the same `randomness`, `participant_count`, and `winner_count`,
///   the function always returns the same indices
/// - This allows anyone to independently verify the results
///
/// # Modulo Bias Mitigation
/// The algorithm uses rejection sampling to avoid modulo bias:
/// ```
/// let max_valid = u64::MAX - (u64::MAX % remaining);
/// // Only accept random values below max_valid
/// // This ensures uniform distribution
/// ```
///
/// # Arguments
/// * `randomness` - The 32-byte random seed (from slot hash + participant root)
/// * `participant_count` - Total number of participants
/// * `winner_count` - Number of winners to select
///
/// # Returns
/// * `Vec<u64>` - The indices of the selected winners
///
/// # Example
/// ```
/// use provable_fairness_shared::select_winner_indices;
///
/// let randomness = [5u8; 32];
/// let participants = 100;
/// let winners = 10;
///
/// let indices = select_winner_indices(&randomness, participants, winners);
/// assert_eq!(indices.len(), winners as usize);
/// // All indices are unique and within range
/// ```
pub fn select_winner_indices(
    randomness: &[u8; 32],
    participant_count: u64,
    winner_count: u64,
) -> Vec<u64> {
    // Clamp to valid ranges
    let winner_count = winner_count.min(participant_count).min(MAX_WINNERS);

    let mut overrides: Vec<(u64, u64)> = Vec::with_capacity(winner_count as usize);
    let mut winners = Vec::with_capacity(winner_count as usize);
    let mut seed = *randomness;

    // Fisher-Yates shuffle with deterministic random numbers
    for i in 0..winner_count {
        let remaining = participant_count - i;

        // Rejection sampling to avoid modulo bias
        let max_valid = u64::MAX - (u64::MAX % remaining);

        let offset = loop {
            seed = solana_keccak_hasher::hash(&seed).to_bytes();
            let rand_u64 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
            if rand_u64 < max_valid {
                break rand_u64 % remaining;
            }
        };

        let j = i + offset;
        let picked = virtual_get(&overrides, j);
        winners.push(picked);

        let value_at_i = virtual_get(&overrides, i);
        overrides.push((j, value_at_i));
    }

    winners
}

// FEE CALCULATION

/// Calculate the platform fee for a giveaway.
///
/// The fee is calculated as 5,000 lamports per participant,
/// clamped between 50,000 and 500,000,000 lamports.
///
/// # Fee Structure
/// - **Base**: 5,000 lamports per participant
/// - **Minimum**: 50,000 lamports (~$0.005 USD)
/// - **Maximum**: 500,000,000 lamports (~$50.00 USD)
///
/// # Arguments
/// * `participant_count` - Number of participants
///
/// # Returns
/// * `u64` - The platform fee in lamports
///
/// # Example
/// ```
/// use provable_fairness_shared::calculate_platform_fee;
///
/// assert_eq!(calculate_platform_fee(1), 50_000);        // Min fee
/// assert_eq!(calculate_platform_fee(100), 500_000);     // 100 * 5,000
/// assert_eq!(calculate_platform_fee(200_000), 500_000_000); // Max fee
/// ```
pub fn calculate_platform_fee(participant_count: u64) -> u64 {
    let fee_per_participant: u64 = 5_000;
    let fee = participant_count * fee_per_participant;
    let min_fee: u64 = 50_000;
    let max_fee: u64 = 500_000_000;
    fee.clamp(min_fee, max_fee)
}

// VERIFICATION HELPERS

/// Verify that a set of winner indices is valid.
///
/// This checks that:
/// 1. All indices are within the participant range
/// 2. All indices are unique
/// 3. The number of winners matches the expected count
///
/// # Arguments
/// * `indices` - The winner indices to verify
/// * `participant_count` - Total number of participants
/// * `expected_count` - Expected number of winners
///
/// # Returns
/// * `bool` - True if the indices are valid
///
/// # Example
/// ```
/// use provable_fairness_shared::verify_winner_indices;
///
/// let indices = vec![0, 2, 5];
/// assert!(verify_winner_indices(&indices, 10, 3));
/// assert!(!verify_winner_indices(&indices, 5, 3)); // Index 5 is out of range
/// assert!(!verify_winner_indices(&indices, 10, 2)); // Wrong count
/// ```
pub fn verify_winner_indices(indices: &[u64], participant_count: u64, expected_count: u64) -> bool {
    if indices.len() != expected_count as usize {
        return false;
    }

    let mut seen = std::collections::HashSet::new();
    for &idx in indices {
        if idx >= participant_count {
            return false;
        }
        if !seen.insert(idx) {
            return false; // Duplicate
        }
    }

    true
}

/// Compute the Merkle root from a list of leaves.
///
/// This is a simple Merkle tree implementation that anyone can use to
/// verify participant or winner roots.
///
/// # Arguments
/// * `leaves` - List of leaf hashes (each 32 bytes)
///
/// # Returns
/// * `[u8; 32]` - The Merkle root
///
/// # Note
/// For large lists (>100,000 leaves), consider using a more efficient
/// implementation. This is provided for verification purposes.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut current = leaves.to_vec();

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);

        for chunk in current.chunks(2) {
            let left = &chunk[0];
            let right = if chunk.len() == 2 { &chunk[1] } else { left };

            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(left);
            combined[32..].copy_from_slice(right);
            next.push(solana_keccak_hasher::hash(&combined).to_bytes());
        }

        current = next;
    }

    current[0]
}

// TESTING HELPERS

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::hash::Hash;
    use solana_sdk::sysvar::slot_hashes::SlotHashes;

    #[test]
    fn test_display_count() {
        assert_eq!(display_count(0), 0);
        assert_eq!(display_count(1), 1);
        assert_eq!(display_count(5), 5);
        assert_eq!(display_count(6), 6);
        assert_eq!(display_count(10), 6);
        assert_eq!(display_count(100), 6);
    }

    #[test]
    fn test_find_slot_hash() {
        let mut slot_hashes = SlotHashes::default();
        let target_slot = 100;
        let target_hash = Hash::new_unique();

        slot_hashes.add(target_slot, target_hash);

        let data = bincode::serialize(&slot_hashes).unwrap();
        let found = find_slot_hash(&data, target_slot);

        assert!(found.is_some());
        assert_eq!(found.unwrap(), target_hash.to_bytes());
    }

    #[test]
    fn test_find_slot_hash_expired() {
        let slot_hashes = SlotHashes::default();
        let data = bincode::serialize(&slot_hashes).unwrap();
        let found = find_slot_hash(&data, 100);

        assert!(found.is_none());
    }

    #[test]
    fn test_derive_randomness() {
        let slot_hash = [1u8; 32];
        let participant_root = [2u8; 32];

        let randomness = derive_randomness(&slot_hash, &participant_root);
        let randomness2 = derive_randomness(&slot_hash, &participant_root);

        // Deterministic
        assert_eq!(randomness, randomness2);

        // Different inputs = different outputs
        let different_slot = [3u8; 32];
        let randomness3 = derive_randomness(&different_slot, &participant_root);
        assert_ne!(randomness, randomness3);

        let different_root = [4u8; 32];
        let randomness4 = derive_randomness(&slot_hash, &different_root);
        assert_ne!(randomness, randomness4);
    }

    #[test]
    fn test_select_winner_indices() {
        let randomness = [5u8; 32];
        let participant_count = 100;
        let winner_count = 10;

        let winners = select_winner_indices(&randomness, participant_count, winner_count);

        // Correct count
        assert_eq!(winners.len(), winner_count as usize);

        // All unique
        let mut sorted = winners.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), winners.len());

        // All in range
        for &idx in &winners {
            assert!(idx < participant_count);
        }

        // Deterministic
        let winners2 = select_winner_indices(&randomness, participant_count, winner_count);
        assert_eq!(winners, winners2);

        // Different randomness = different results
        let different_randomness = [6u8; 32];
        let winners3 =
            select_winner_indices(&different_randomness, participant_count, winner_count);
        assert_ne!(winners, winners3);
    }

    #[test]
    fn test_select_winner_indices_edge_cases() {
        let randomness = [7u8; 32];

        // Winner count > participant count
        let winners = select_winner_indices(&randomness, 5, 10);
        assert_eq!(winners.len(), 5);

        // Winner count = 0
        let winners = select_winner_indices(&randomness, 5, 0);
        assert_eq!(winners.len(), 0);

        // Winner count > MAX_WINNERS
        let winners = select_winner_indices(&randomness, 100_000, 20_000);
        assert_eq!(winners.len(), MAX_WINNERS as usize);
    }

    #[test]
    fn test_calculate_platform_fee() {
        assert_eq!(calculate_platform_fee(1), 50_000);
        assert_eq!(calculate_platform_fee(100), 500_000);
        assert_eq!(calculate_platform_fee(100_000), 500_000_000);
        assert_eq!(calculate_platform_fee(200_000), 500_000_000);
    }

    #[test]
    fn test_verify_winner_indices() {
        let indices = vec![0, 2, 5];

        assert!(verify_winner_indices(&indices, 10, 3));
        assert!(!verify_winner_indices(&indices, 5, 3)); // Index 5 out of range
        assert!(!verify_winner_indices(&indices, 10, 2)); // Wrong count

        let duplicate = vec![0, 0, 2];
        assert!(!verify_winner_indices(&duplicate, 10, 3));
    }

    #[test]
    fn test_compute_merkle_root() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];

        let leaves = vec![leaf1, leaf2, leaf3];
        let root = compute_merkle_root(&leaves);

        // Deterministic
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root, root2);

        // Different leaves = different root
        let different_leaves = vec![leaf1, leaf2, leaf3, [4u8; 32]];
        let root3 = compute_merkle_root(&different_leaves);
        assert_ne!(root, root3);

        // Empty leaves returns zero
        let root4 = compute_merkle_root(&[]);
        assert_eq!(root4, [0u8; 32]);
    }
}
