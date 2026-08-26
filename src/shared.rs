// Shared utilities for the Provable Fairness System
use solana_keccak_hasher;

pub const MAX_DISPLAYED_WINNERS: usize = 6;
pub const MAX_PARTICIPANTS: u64 = 100_000;
pub const MAX_WINNERS: u64 = 10_000;
pub const REVEAL_DELAY_SLOTS: u64 = 150;
pub const MAX_REVEAL_WINDOW: u64 = 450;

pub fn display_count(winner_count: u64) -> usize {
    core::cmp::min(winner_count as usize, MAX_DISPLAYED_WINNERS)
}

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

pub fn derive_randomness(target_hash: &[u8; 32], participant_root: &[u8; 32]) -> [u8; 32] {
    let mut combined_seed = [0u8; 64];
    combined_seed[..32].copy_from_slice(target_hash);
    combined_seed[32..].copy_from_slice(participant_root);
    solana_keccak_hasher::hash(&combined_seed).to_bytes()
}

fn virtual_get(overrides: &[(u64, u64)], i: u64) -> u64 {
    for &(k, v) in overrides.iter().rev() {
        if k == i {
            return v;
        }
    }
    i
}

pub fn select_winner_indices(
    randomness: &[u8; 32],
    participant_count: u64,
    winner_count: u64,
) -> Vec<u64> {
    let winner_count = winner_count.min(participant_count).min(MAX_WINNERS);

    let mut overrides: Vec<(u64, u64)> = Vec::with_capacity(winner_count as usize);
    let mut winners = Vec::with_capacity(winner_count as usize);
    let mut seed = *randomness;

    for i in 0..winner_count {
        let remaining = participant_count - i;
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

pub fn calculate_platform_fee(participant_count: u64) -> u64 {
    let fee_per_participant: u64 = 5_000;
    let fee = participant_count * fee_per_participant;
    let min_fee: u64 = 50_000;
    let max_fee: u64 = 500_000_000;
    fee.clamp(min_fee, max_fee)
}

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
            return false;
        }
    }

    true
}

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
