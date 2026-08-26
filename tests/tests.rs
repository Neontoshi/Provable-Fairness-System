// tests/tests.rs
//! Integration tests for the Provable Fairness System

use anchor_lang::solana_program::hash::Hash;
use anchor_lang::solana_program::sysvar::slot_hashes::SlotHashes;
use provable_fairness_system::{
    calculate_platform_fee, derive_randomness, display_count, find_slot_hash,
    select_winner_indices, MAX_WINNERS,
};

// UTILITY FUNCTION TESTS
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
    let winners3 = select_winner_indices(&different_randomness, participant_count, winner_count);
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
fn test_winner_indices_verification() {
    // Test that select_winner_indices produces valid indices
    let randomness = [8u8; 32];
    let participant_count = 50;
    let winner_count = 5;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);

    // Verify all indices are within bounds
    assert!(winners.iter().all(|&idx| idx < participant_count));

    // Verify all indices are unique
    let mut seen = std::collections::HashSet::new();
    assert!(winners.iter().all(|&idx| seen.insert(idx)));
}

#[test]
fn test_fisher_yates_uniformity() {
    // Test that the Fisher-Yates algorithm produces roughly uniform results
    let randomness = [9u8; 32];
    let participant_count = 10;
    let winner_count = 5;

    // Run multiple times with different seeds
    let mut results = std::collections::HashMap::new();
    for seed in 0..100 {
        let mut rng = randomness;
        rng[0] = seed as u8;
        let winners = select_winner_indices(&rng, participant_count, winner_count);
        for &idx in &winners {
            *results.entry(idx).or_insert(0) += 1;
        }
    }

    // Each index should appear roughly 50 times (100 runs * 5 winners / 10 participants)
    // Allow some variance
    for count in results.values() {
        assert!(
            *count > 30 && *count < 70,
            "Index appeared {} times, expected ~50",
            count
        );
    }
}

// PERFORMANCE TESTS

#[test]
fn test_select_winner_indices_performance() {
    let randomness = [10u8; 32];
    let participant_count = 100_000;
    let winner_count = 10_000;

    let start = std::time::Instant::now();
    let winners = select_winner_indices(&randomness, participant_count, winner_count);
    let duration = start.elapsed();

    // Should complete in reasonable time
    assert!(
        duration.as_millis() < 1000,
        "Took {}ms",
        duration.as_millis()
    );
    assert_eq!(winners.len(), winner_count as usize);
}

// RANDOMNESS QUALITY TESTS

#[test]
fn test_randomness_derivation_quality() {
    // Test that small changes in inputs produce large changes in output
    let base_hash = [1u8; 32];
    let base_root = [2u8; 32];

    let base_randomness = derive_randomness(&base_hash, &base_root);

    // Change one bit in the hash
    let mut modified_hash = base_hash;
    modified_hash[0] ^= 1;
    let modified_randomness = derive_randomness(&modified_hash, &base_root);
    assert_ne!(base_randomness, modified_randomness);

    // Change one bit in the root
    let mut modified_root = base_root;
    modified_root[0] ^= 1;
    let modified_randomness = derive_randomness(&base_hash, &modified_root);
    assert_ne!(base_randomness, modified_randomness);
}

#[test]
fn test_slot_hash_finding() {
    // Test with a realistic slot hashes data structure
    let mut slot_hashes = SlotHashes::default();

    // Add some slots
    for slot in 100..200 {
        let hash = Hash::new_unique();
        slot_hashes.add(slot, hash);
    }

    let data = bincode::serialize(&slot_hashes).unwrap();

    // Test finding a slot that exists
    let found = find_slot_hash(&data, 150);
    assert!(found.is_some());

    // Test finding a slot that doesn't exist
    let found = find_slot_hash(&data, 999);
    assert!(found.is_none());
}

// PROPERTY-BASED TESTS
#[test]
fn test_select_winner_indices_properties() {
    let randomness = [11u8; 32];
    let participant_count = 1000;
    let winner_count = 100;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);

    // Property 1: Correct number of winners
    assert_eq!(winners.len(), winner_count as usize);

    // Property 2: All indices are within the valid range
    assert!(winners.iter().all(|&idx| idx < participant_count));

    // Property 3: All indices are unique
    let unique_count: std::collections::HashSet<_> = winners.iter().collect();
    assert_eq!(unique_count.len(), winners.len());

    // Property 4: Same inputs produce same outputs
    let winners2 = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners, winners2);
}

// FEE CALCULATION PROPERTIES

#[test]
fn test_fee_calculation_properties() {
    // Property 1: Fee is monotonic (increases with participant count)
    assert!(calculate_platform_fee(10) <= calculate_platform_fee(100));
    assert!(calculate_platform_fee(100) <= calculate_platform_fee(1000));

    // Property 2: Fee is never below minimum
    assert!(calculate_platform_fee(0) >= 50_000);
    assert!(calculate_platform_fee(1) >= 50_000);
    assert!(calculate_platform_fee(10) >= 50_000);

    // Property 3: Fee is never above maximum
    assert!(calculate_platform_fee(100_000) <= 500_000_000);
    assert!(calculate_platform_fee(200_000) <= 500_000_000);

    // Property 4: Fee calculation is deterministic
    assert_eq!(calculate_platform_fee(42), calculate_platform_fee(42));
}

// EDGE CASE TESTS

#[test]
fn test_edge_case_large_participant_count() {
    let randomness = [12u8; 32];
    let participant_count = 100_000; // Maximum
    let winner_count = 10_000; // Maximum

    let winners = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners.len(), winner_count as usize);

    // All indices should be within 0..100_000
    assert!(winners.iter().all(|&idx| idx < participant_count));
}

#[test]
fn test_edge_case_single_participant() {
    let randomness = [13u8; 32];
    let participant_count = 1;
    let winner_count = 1;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners, vec![0]);
}

#[test]
fn test_edge_case_winner_count_one() {
    let randomness = [14u8; 32];
    let participant_count = 1000;
    let winner_count = 1;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners.len(), 1);
    assert!(winners[0] < participant_count);
}

#[test]
fn test_edge_case_all_participants_win() {
    let randomness = [15u8; 32];
    let participant_count = 50;
    let winner_count = 50;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners.len(), 50);

    // When winner_count == participant_count, the result should be a permutation of 0..n-1
    let mut sorted = winners.clone();
    sorted.sort();
    assert_eq!(sorted, (0..50).collect::<Vec<u64>>());
}
