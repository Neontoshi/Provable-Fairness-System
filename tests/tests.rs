// tests/tests.rs
use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::sysvar::slot_hashes::SlotHashes;
use anchor_lang::InstructionData;
use anchor_lang::ToAccountMetas;
use provable_fairness_system::{
    calculate_platform_fee, derive_randomness, display_count, find_slot_hash, select_winner_indices,
    GiveawayData, UserState, MAX_REVEAL_WINDOW, REVEAL_DELAY_SLOTS,
};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::Instruction,
    pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    sysvar::Sysvar,
    transaction::Transaction,
};
use std::str::FromStr;

/// The program ID (must match the one in lib.rs)
const PROGRAM_ID: Pubkey = pubkey!("EGJ9Y7baCg7MrPatH8myHmmKWqFHDPMeFCSUw9vwdnr3");

/// Treasury address (must match the one in lib.rs)
const TREASURY: Pubkey = pubkey!("AoUY8D1M3X7fbgHy4XpgXqhpVSnLKgwfjnrC1ByAFXHU");

/// Keeper address (must match the one in lib.rs)
const KEEPER: Pubkey = pubkey!("HLxD5xGPBGv5X7nhK2agHvsP7Yu7tGmnPLmLdS8PcAqy");

/// A test fixture that sets up a ProgramTest with the provable fairness program.
fn setup_program_test() -> (ProgramTest, Keypair) {
    let mut program_test = ProgramTest::new(
        "provable_fairness_system",
        PROGRAM_ID,
        processor!(provable_fairness_system::entry),
    );

    // Add the treasury account with some SOL for testing
    let treasury_account = Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: system_program::ID,
        executable: false,
        rent_epoch: 0,
    };
    program_test.add_account(TREASURY, treasury_account);

    // Add the keeper account
    let keeper_account = Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: system_program::ID,
        executable: false,
        rent_epoch: 0,
    };
    program_test.add_account(KEEPER, keeper_account);

    // Create a wallet for the test authority
    let authority = Keypair::new();

    // Fund the authority
    program_test.add_account(
        authority.pubkey(),
        Account {
            lamports: 100_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    (program_test, authority)
}

/// Helper to simulate slot advancement and sysvar updates.
async fn advance_slots(context: &mut ProgramTestContext, num_slots: u64) -> Result<(), BanksClientError> {
    let mut slot_hashes = SlotHashes::default();

    for _ in 0..num_slots {
        // Update the slot in the context
        context.warp_to_slot(context.banks_client.get_root_slot().await.unwrap() + 1).unwrap();

        // Get the current slot from the clock
        let clock = context.banks_client.get_sysvar::<Clock>().await.unwrap();
        let current_slot = clock.slot;

        // Add a dummy hash to the slot hashes sysvar
        let hash = solana_sdk::hash::Hash::new_unique();
        slot_hashes.add(current_slot, hash);
    }

    // Update the slot hashes sysvar account
    let slot_hashes_data = bincode::serialize(&slot_hashes).unwrap();
    context.set_sysvar(&slot_hashes_data);

    Ok(())
}

/// Helper to get the user state PDA.
fn get_user_state_pda(authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"user_state", authority.as_ref()], &PROGRAM_ID).0
}

/// Helper to get the user giveaways PDA for a specific account index.
fn get_user_giveaways_pda(authority: &Pubkey, account_index: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"user",
            authority.as_ref(),
            &account_index.to_le_bytes(),
        ],
        &PROGRAM_ID,
    )
    0
}

/// Helper to create a transaction with multiple instructions.
async fn send_transaction(
    context: &mut ProgramTestContext,
    instructions: Vec<Instruction>,
    signers: Vec<&Keypair>,
) -> Result<(), BanksClientError> {
    let mut tx = Transaction::new_with_payer(&instructions, Some(&context.payer.pubkey()));
    let mut all_signers = vec![&context.payer];
    all_signers.extend(signers);
    tx.sign(&all_signers, context.banks_client.get_latest_blockhash().await.unwrap());
    context.banks_client.process_transaction(tx).await
}

/// Helper to create a user state account.
async fn create_user_state(
    context: &mut ProgramTestContext,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());

    let instruction = provable_fairness_system::instruction::InitializeUser {
        user_state: user_state_pda,
        authority: authority.pubkey(),
        system_program: system_program::ID,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    send_transaction(context, vec![ix], vec![authority]).await
}

/// Helper to create a user account.
async fn create_user_account(
    context: &mut ProgramTestContext,
    authority: &Keypair,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());

    // First, get the current user state to determine the next account index
    let user_state_account = context.banks_client.get_account(user_state_pda).await.unwrap().unwrap();
    let user_state: UserState = bincode::deserialize(&user_state_account.data[8..]).unwrap();
    let next_account_index = user_state.total_accounts + 1;

    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), next_account_index);

    let instruction = provable_fairness_system::instruction::CreateUserAccount {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        system_program: system_program::ID,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    send_transaction(context, vec![ix], vec![authority]).await
}

/// Helper to create a giveaway.
async fn create_giveaway(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    participant_count: u64,
    winner_count: u64,
    participant_root: [u8; 32],
    platform_fee: u64,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    // Create the fee transfer instruction if platform_fee > 0
    let mut instructions = vec![];
    if platform_fee > 0 {
        let transfer_ix = system_instruction::transfer(
            &authority.pubkey(),
            &TREASURY,
            platform_fee,
        );
        instructions.push(transfer_ix);
    }

    let instruction = provable_fairness_system::instruction::CreateGiveaway {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        treasury: TREASURY,
        system_program: system_program::ID,
        instructions_sysvar: solana_sdk::sysvar::instructions::ID,
        account_index,
        id: format!("test-{}", participant_count),
        participant_root,
        participant_count,
        winner_count,
        platform_fee,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };
    instructions.push(ix);

    send_transaction(context, instructions, vec![authority]).await
}

/// Helper to create and commit a giveaway in one transaction.
async fn create_and_commit_giveaway(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    participant_count: u64,
    winner_count: u64,
    participant_root: [u8; 32],
    platform_fee: u64,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    // Create the fee transfer instruction if platform_fee > 0
    let mut instructions = vec![];
    if platform_fee > 0 {
        let transfer_ix = system_instruction::transfer(
            &authority.pubkey(),
            &TREASURY,
            platform_fee,
        );
        instructions.push(transfer_ix);
    }

    let instruction = provable_fairness_system::instruction::CreateAndCommitGiveaway {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        treasury: TREASURY,
        system_program: system_program::ID,
        instructions_sysvar: solana_sdk::sysvar::instructions::ID,
        account_index,
        id: format!("test-{}", participant_count),
        participant_root,
        participant_count,
        winner_count,
        platform_fee,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };
    instructions.push(ix);

    send_transaction(context, instructions, vec![authority]).await
}

/// Helper to commit a draw.
async fn commit_draw(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    giveaway_index: u64,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    let instruction = provable_fairness_system::instruction::CommitDraw {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        account_index,
        giveaway_index,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    send_transaction(context, vec![ix], vec![authority]).await
}

/// Helper to reveal a draw (simulating the keeper).
async fn reveal_draw(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    giveaway_index: u64,
    randomness: [u8; 32],
    winners: Vec<provable_fairness_system::Winner>,
    winner_root: [u8; 32],
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    let keeper_keypair = Keypair::from_bytes(&[0u8; 64]).unwrap(); // This won't actually be used for signing

    let instruction = provable_fairness_system::instruction::RevealDraw {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        payer: KEEPER,
        slot_hashes: solana_sdk::sysvar::slot_hashes::ID,
        account_index,
        giveaway_index,
        randomness,
        winners,
        winner_root,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    send_transaction(context, vec![ix], vec![&keeper_keypair]).await
}

/// Helper to cancel a giveaway.
async fn cancel_giveaway(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    giveaway_index: u64,
) -> Result<(), BanksClientError> {
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    let instruction = provable_fairness_system::instruction::CancelGiveaway {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        account_index,
        giveaway_index,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    send_transaction(context, vec![ix], vec![authority]).await
}

/// Helper to get a giveaway from the user account.
async fn get_giveaway(
    context: &mut ProgramTestContext,
    authority: &Keypair,
    account_index: u64,
    giveaway_index: u64,
) -> GiveawayData {
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), account_index);

    let account = context.banks_client.get_account(user_giveaways_pda).await.unwrap().unwrap();

    // Deserialize the account data (skip the 8-byte discriminator)
    let data = &account.data[8..];
    bincode::deserialize::<provable_fairness_system::UserGiveaways>(data)
        .unwrap()
        .giveaways
        .get(giveaway_index as usize)
        .unwrap()
        .clone()
}

// UTILITY TESTS

#[tokio::test]
async fn test_find_slot_hash() {
    let mut slot_hashes = SlotHashes::default();
    let target_slot = 100;
    let target_hash = solana_sdk::hash::Hash::new_unique();

    slot_hashes.add(target_slot, target_hash);

    let data = bincode::serialize(&slot_hashes).unwrap();
    let found = find_slot_hash(&data, target_slot);

    assert!(found.is_some());
    assert_eq!(found.unwrap(), target_hash.to_bytes());
}

#[tokio::test]
async fn test_find_slot_hash_expired() {
    let slot_hashes = SlotHashes::default();
    let data = bincode::serialize(&slot_hashes).unwrap();
    let found = find_slot_hash(&data, 100);

    assert!(found.is_none());
}

#[tokio::test]
async fn test_derive_randomness() {
    let slot_hash = [1u8; 32];
    let participant_root = [2u8; 32];

    let randomness = derive_randomness(&slot_hash, &participant_root);

    // Randomness should be deterministic
    let randomness2 = derive_randomness(&slot_hash, &participant_root);
    assert_eq!(randomness, randomness2);

    // Different inputs should produce different outputs
    let different_slot = [3u8; 32];
    let randomness3 = derive_randomness(&different_slot, &participant_root);
    assert_ne!(randomness, randomness3);

    let different_root = [4u8; 32];
    let randomness4 = derive_randomness(&slot_hash, &different_root);
    assert_ne!(randomness, randomness4);
}

#[tokio::test]
async fn test_select_winner_indices() {
    let randomness = [5u8; 32];
    let participant_count = 100;
    let winner_count = 10;

    let winners = select_winner_indices(&randomness, participant_count, winner_count);

    // Should select the correct number of winners
    assert_eq!(winners.len(), winner_count as usize);

    // All indices should be unique
    let mut sorted = winners.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), winners.len());

    // All indices should be within range
    for &idx in &winners {
        assert!(idx < participant_count);
    }

    // Should be deterministic
    let winners2 = select_winner_indices(&randomness, participant_count, winner_count);
    assert_eq!(winners, winners2);

    // Different randomness should produce different results
    let different_randomness = [6u8; 32];
    let winners3 = select_winner_indices(&different_randomness, participant_count, winner_count);
    assert_ne!(winners, winners3);
}

#[tokio::test]
async fn test_select_winner_indices_edge_cases() {
    let randomness = [7u8; 32];

    // Winner count > participant count
    let winners = select_winner_indices(&randomness, 5, 10);
    assert_eq!(winners.len(), 5);

    // Winner count = 0
    let winners = select_winner_indices(&randomness, 5, 0);
    assert_eq!(winners.len(), 0);

    // Winner count > MAX_WINNERS
    let winners = select_winner_indices(&randomness, 100_000, 20_000);
    assert_eq!(winners.len(), provable_fairness_system::MAX_WINNERS as usize);
}

#[tokio::test]
async fn test_calculate_platform_fee() {
    // Small participant count
    let fee = calculate_platform_fee(1);
    assert_eq!(fee, 50_000); // Min fee

    // Medium participant count
    let fee = calculate_platform_fee(100);
    assert_eq!(fee, 500_000); // 100 * 5,000

    // Large participant count
    let fee = calculate_platform_fee(100_000);
    assert_eq!(fee, 500_000_000);

    // Participant count that should be clamped
    let fee = calculate_platform_fee(200_000);
    assert_eq!(fee, 500_000_000);
}

#[tokio::test]
async fn test_display_count() {
    assert_eq!(display_count(0), 0);
    assert_eq!(display_count(1), 1);
    assert_eq!(display_count(5), 5);
    assert_eq!(display_count(6), 6);
    assert_eq!(display_count(10), 6);
    assert_eq!(display_count(100), 6);
}

#[tokio::test]
async fn test_initialize_user() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state
    create_user_state(&mut context, &authority).await.unwrap();

    // Verify the account was created
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let account = context.banks_client.get_account(user_state_pda).await.unwrap().unwrap();

    // Deserialize and verify
    let user_state: UserState = bincode::deserialize(&account.data[8..]).unwrap();
    assert_eq!(user_state.authority, authority.pubkey());
    assert_eq!(user_state.total_accounts, 0);
}

#[tokio::test]
async fn test_create_user_account() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state
    create_user_state(&mut context, &authority).await.unwrap();

    // Create a user account
    create_user_account(&mut context, &authority).await.unwrap();

    // Verify the account was created
    let user_state_pda = get_user_state_pda(&authority.pubkey());
    let user_state_account = context.banks_client.get_account(user_state_pda).await.unwrap().unwrap();
    let user_state: UserState = bincode::deserialize(&user_state_account.data[8..]).unwrap();
    assert_eq!(user_state.total_accounts, 1);

    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), 1);
    let account = context.banks_client.get_account(user_giveaways_pda).await.unwrap().unwrap();
    assert!(account.data.len() > 0);
}

#[tokio::test]
async fn test_create_giveaway() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [1u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Verify the giveaway was created
    let giveaway_data = get_giveaway(&mut context, &authority, 1, 0).await;
    assert_eq!(giveaway_data.participant_root, participant_root);
    assert_eq!(giveaway_data.participant_count, participant_count);
    assert_eq!(giveaway_data.winner_count, winner_count);
    assert_eq!(giveaway_data.state, 0); // Created
    assert_eq!(giveaway_data.commit_slot, 0);
    assert_eq!(giveaway_data.reveal_slot, 0);
}

#[tokio::test]
async fn test_create_and_commit_giveaway() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Get the current slot
    let initial_slot = context.banks_client.get_root_slot().await.unwrap();

    // Create and commit a giveaway
    let participant_root = [2u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_and_commit_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Advance the slot a bit to get the commit slot
    advance_slots(&mut context, 1).await.unwrap();

    // Verify the giveaway was created with committed state
    let giveaway_data = get_giveaway(&mut context, &authority, 1, 0).await;
    assert_eq!(giveaway_data.participant_root, participant_root);
    assert_eq!(giveaway_data.participant_count, participant_count);
    assert_eq!(giveaway_data.winner_count, winner_count);
    assert_eq!(giveaway_data.state, 1); // Committed

    // Verify commit and reveal slots are set
    assert!(giveaway_data.commit_slot > initial_slot);
    assert_eq!(giveaway_data.reveal_slot, giveaway_data.commit_slot + REVEAL_DELAY_SLOTS);
}

#[tokio::test]
async fn test_commit_reveal_flow() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [3u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Commit the draw
    commit_draw(&mut context, &authority, 1, 0).await.unwrap();

    // Verify the state changed to committed
    let giveaway_data = get_giveaway(&mut context, &authority, 1, 0).await;
    assert_eq!(giveaway_data.state, 1);
    assert!(giveaway_data.commit_slot > 0);
    assert!(giveaway_data.reveal_slot > 0);

    // Advance slots past the reveal delay
    advance_slots(&mut context, REVEAL_DELAY_SLOTS + 5).await.unwrap();

    // Get the current slot
    let current_slot = context.banks_client.get_root_slot().await.unwrap();

    // Derive randomness
    let randomness = derive_randomness(&[4u8; 32], &participant_root);

    // Create winners
    let winners = vec![
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner1".to_string(),
        },
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner2".to_string(),
        },
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner3".to_string(),
        },
    ];
    let winner_root = [5u8; 32];

    // Reveal the draw
    reveal_draw(
        &mut context,
        &authority,
        1,
        0,
        randomness,
        winners.clone(),
        winner_root,
    )
    .await
    .unwrap();

    // Verify the state changed to drawn
    let giveaway_data = get_giveaway(&mut context, &authority, 1, 0).await;
    assert_eq!(giveaway_data.state, 2);
    assert_eq!(giveaway_data.winner_root, winner_root);
}

#[tokio::test]
async fn test_reveal_requires_committed_state() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway (not committed)
    let participant_root = [6u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Try to reveal without committing
    let randomness = [7u8; 32];
    let winners = vec![];
    let winner_root = [8u8; 32];

    let result = reveal_draw(
        &mut context,
        &authority,
        1, // account_index
        0, // giveaway_index
        randomness,
        winners,
        winner_root,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_reveal_too_early() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [9u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Commit the draw
    commit_draw(&mut context, &authority, 1, 0).await.unwrap();

    // Try to reveal immediately (before the delay)
    let randomness = [10u8; 32];
    let winners = vec![];
    let winner_root = [11u8; 32];

    let result = reveal_draw(
        &mut context,
        &authority,
        1, // account_index
        0, // giveaway_index
        randomness,
        winners,
        winner_root,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_reveal_window_expired() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [12u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Commit the draw
    commit_draw(&mut context, &authority, 1, 0).await.unwrap();

    // Advance slots past the MAX_REVEAL_WINDOW
    advance_slots(&mut context, MAX_REVEAL_WINDOW + 10).await.unwrap();

    // Try to reveal (should fail - slot hash expired)
    let randomness = [13u8; 32];
    let winners = vec![];
    let winner_root = [14u8; 32];

    let result = reveal_draw(
        &mut context,
        &authority,
        1, // account_index
        0, // giveaway_index
        randomness,
        winners,
        winner_root,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_cancel_giveaway() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [15u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Cancel the giveaway
    cancel_giveaway(&mut context, &authority, 1, 0).await.unwrap();

    // Verify the state changed to cancelled
    let giveaway_data = get_giveaway(&mut context, &authority, 1, 0).await;
    assert_eq!(giveaway_data.state, 3);
}

#[tokio::test]
async fn test_cancel_after_commit_fails() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway
    let participant_root = [16u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Commit the draw
    commit_draw(&mut context, &authority, 1, 0).await.unwrap();

    // Try to cancel (should fail - state is committed)
    let result = cancel_giveaway(&mut context, &authority, 1, 0).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_cancel_after_drawn_fails() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create and commit a giveaway
    let participant_root = [17u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_and_commit_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Try to cancel (should fail - state is committed)
    let result = cancel_giveaway(&mut context, &authority, 1, 0).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_multiple_giveaways_per_account() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    let num_giveaways = 5;
    let participant_root_base = [18u8; 32];

    for i in 0..num_giveaways {
        let mut participant_root = participant_root_base;
        participant_root[0] = i as u8;

        create_giveaway(
            &mut context,
            &authority,
            1, // account_index
            10 + i,
            3 + (i % 3),
            participant_root,
            50_000, // Minimum fee
        )
        .await
        .unwrap();

        // Verify each giveaway was created with the correct index
        let giveaway_data = get_giveaway(&mut context, &authority, 1, i as u64).await;
        assert_eq!(giveaway_data.participant_root, participant_root);
        assert_eq!(giveaway_data.state, 0);
    }

    // Verify total count
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), 1);
    let account = context.banks_client.get_account(user_giveaways_pda).await.unwrap().unwrap();
    let data = &account.data[8..];
    let user_giveaways: provable_fairness_system::UserGiveaways = bincode::deserialize(data).unwrap();
    assert_eq!(user_giveaways.giveaways.len(), num_giveaways);
    assert_eq!(user_giveaways.giveaway_count, num_giveaways);
}

#[tokio::test]
async fn test_fee_verification() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create a giveaway with an incorrect fee (should fail)
    let participant_root = [19u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let incorrect_fee = 1_000; // Wrong amount

    let result = create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        incorrect_fee,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_max_participants_enforced() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Try to create a giveaway with too many participants
    let participant_root = [20u8; 32];
    let participant_count = 200_000; // > MAX_PARTICIPANTS
    let winner_count = 10;
    let platform_fee = calculate_platform_fee(participant_count);

    let result = create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_max_winners_enforced() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Try to create a giveaway with too many winners
    let participant_root = [21u8; 32];
    let participant_count = 10_000;
    let winner_count = 20_000; // > MAX_WINNERS
    let platform_fee = calculate_platform_fee(participant_count);

    let result = create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_close_user_account() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Create and commit a giveaway
    let participant_root = [22u8; 32];
    let participant_count = 10;
    let winner_count = 3;
    let platform_fee = calculate_platform_fee(participant_count);

    create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await
    .unwrap();

    // Try to close before drawing (should fail)
    let user_giveaways_pda = get_user_giveaways_pda(&authority.pubkey(), 1);
    let user_state_pda = get_user_state_pda(&authority.pubkey());

    let instruction = provable_fairness_system::instruction::CloseUserAccount {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        account_index: 1,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    let result = send_transaction(&mut context, vec![ix], vec![&authority]).await;
    assert!(result.is_err());

    // Commit the draw
    commit_draw(&mut context, &authority, 1, 0).await.unwrap();

    // Advance slots past reveal delay
    advance_slots(&mut context, REVEAL_DELAY_SLOTS + 5).await.unwrap();

    // Derive randomness
    let randomness = derive_randomness(&[23u8; 32], &participant_root);

    // Create winners
    let winners = vec![
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner1".to_string(),
        },
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner2".to_string(),
        },
        provable_fairness_system::Winner {
            wallet: Pubkey::new_unique(),
            username: "winner3".to_string(),
        },
    ];
    let winner_root = [24u8; 32];

    // Reveal the draw
    reveal_draw(
        &mut context,
        &authority,
        1, // account_index
        0, // giveaway_index
        randomness,
        winners,
        winner_root,
    )
    .await
    .unwrap();

    // Now closing should work (state is drawn)
    let instruction = provable_fairness_system::instruction::CloseUserAccount {
        user_state: user_state_pda,
        user_giveaways: user_giveaways_pda,
        authority: authority.pubkey(),
        account_index: 1,
    };

    let accounts = instruction.to_account_metas(None);
    let data = instruction.data();

    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts,
        data,
    };

    let result = send_transaction(&mut context, vec![ix], vec![&authority]).await;
    assert!(result.is_ok());

    // Verify the account was closed
    let account = context.banks_client.get_account(user_giveaways_pda).await.unwrap();
    assert!(account.is_none());
}

#[tokio::test]
async fn test_zero_participants_fails() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Try to create a giveaway with zero participants
    let participant_root = [25u8; 32];
    let participant_count = 0;
    let winner_count = 0;
    let platform_fee = calculate_platform_fee(participant_count);

    let result = create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_winners_more_than_participants_fails() {
    let (mut program_test, authority) = setup_program_test();
    let context = program_test.start_with_context().await;

    // Initialize the user state and create a user account
    create_user_state(&mut context, &authority).await.unwrap();
    create_user_account(&mut context, &authority).await.unwrap();

    // Try to create a giveaway with more winners than participants
    let participant_root = [26u8; 32];
    let participant_count = 5;
    let winner_count = 10;
    let platform_fee = calculate_platform_fee(participant_count);

    let result = create_giveaway(
        &mut context,
        &authority,
        1, // account_index
        participant_count,
        winner_count,
        participant_root,
        platform_fee,
    )
    .await;

    assert!(result.is_err());
}
