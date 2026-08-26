// provable-fairness-system/src/lib.rs
//! # Provable Fairness System
//!
//! A standalone, open-source library for provably fair winner selection on Solana.
//! This implements the core commit-reveal protocol with Merkle tree verification
//! that enables transparent, verifiable random selection without requiring
//! trust in the organizer.
//!
//! ## Core Concepts
//!
//! ### Commit-Reveal Protocol
//! 1. **Commit**: The organizer commits to a participant list (via Merkle root)
//!    and records the current Solana slot
//! 2. **Wait**: A delay period (default 150 slots, ~60 seconds) ensures the
//!    slot hash cannot be predicted
//! 3. **Reveal**: The slot hash is used as entropy to select winners
//!    deterministically
//!
//! ### Merkle Trees
//! - Participant Merkle Tree: Commits to the full participant list with a single
//!   32-byte root
//! - Winner Merkle Tree: Commits to the winner list for verification
//!
//! ## Usage
//!
//! This library is designed to be embedded in Solana programs using Anchor.
//! See the `giveaway` module for the complete program implementation.

#![allow(unexpected_cfgs)]
#![allow(unknown_lints)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program as system_program_id;

// CONSTANTS

/// Number of slots to wait between commit and reveal.
/// ~60 seconds on Solana mainnet (400ms per slot).
pub const REVEAL_DELAY_SLOTS: u64 = 150;

/// Maximum participants allowed in a single giveaway.
pub const MAX_PARTICIPANTS: u64 = 100_000;

/// Maximum winners allowed in a single giveaway.
pub const MAX_WINNERS: u64 = 10_000;

/// Maximum slots after commit that reveal is still valid.
/// After this window, the slot hash may no longer be available.
pub const MAX_REVEAL_WINDOW: u64 = 450;

/// Maximum accounts per user (for rent efficiency).
pub const MAX_ACCOUNTS_PER_USER: usize = 100;

/// Size of a single giveaway entry in the account data.
/// participant_root: 32 + participant_count: 8 + winner_count: 8 +
/// state: 1 + commit_slot: 8 + reveal_slot: 8 + winner_root: 32 = 97 bytes
pub const GIVEAWAY_DATA_SIZE: usize = 97;

/// Initial space allocation for a user account.
/// Header: 8 (discriminator) + 32 (authority) + 8 (account_index) +
/// 4 (Vec len prefix) + 8 (giveaway_count) + 5 * GIVEAWAY_DATA_SIZE
pub const USER_ACCOUNT_INIT_SPACE: usize = 60 + (5 * GIVEAWAY_DATA_SIZE);

/// Slot hashes sysvar address.
pub const SLOT_HASHES_ID: Pubkey = pubkey!("SysvarS1otHashes111111111111111111111111111");

/// Instructions sysvar address.
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");

/// Maximum number of winners to display in the reveal event.
pub const MAX_DISPLAYED_WINNERS: usize = 6;

/// Convert a winner count to a display count (capped at MAX_DISPLAYED_WINNERS).
pub fn display_count(winner_count: u64) -> usize {
    core::cmp::min(winner_count as usize, MAX_DISPLAYED_WINNERS)
}

/// Find a slot hash in the slot hashes sysvar data.
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
pub fn derive_randomness(target_hash: &[u8; 32], participant_root: &[u8; 32]) -> [u8; 32] {
    let mut combined_seed = [0u8; 64];
    combined_seed[..32].copy_from_slice(target_hash);
    combined_seed[32..].copy_from_slice(participant_root);
    solana_keccak_hasher::hash(&combined_seed).to_bytes()
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

/// Helper for the Fisher-Yates algorithm: get a value from overrides if present.
fn virtual_get(overrides: &[(u64, u64)], i: u64) -> u64 {
    for &(k, v) in overrides.iter().rev() {
        if k == i {
            return v;
        }
    }
    i
}

pub fn calculate_platform_fee(participant_count: u64) -> u64 {
    let fee_per_participant: u64 = 5_000;
    let fee = participant_count * fee_per_participant;
    let min_fee: u64 = 50_000;
    let max_fee: u64 = 500_000_000;
    fee.clamp(min_fee, max_fee)
}

// ANCHOR PROGRAM

declare_id!("EGJ9Y7baCg7MrPatH8myHmmKWqFHDPMeFCSUw9vwdnr3");

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Winner {
    pub wallet: Pubkey,
    pub username: String,
}

#[event]
pub struct WinnersRevealed {
    pub giveaway_index: u64,
    pub randomness: [u8; 32],
    pub winners: Vec<Winner>,
    pub winner_root: [u8; 32],
    pub winner_indices: Vec<u64>,
}

// ACCOUNT STRUCTURES

/// UserState tracks a user's account count.
#[account]
pub struct UserState {
    pub authority: Pubkey,
    pub total_accounts: u64,
}

/// UserGiveaways stores all giveaways for a user account.
#[account]
pub struct UserGiveaways {
    pub authority: Pubkey,
    pub account_index: u64,
    pub giveaways: Vec<GiveawayData>,
    pub giveaway_count: u64,
}

/// Individual giveaway data stored on-chain.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct GiveawayData {
    pub participant_root: [u8; 32],
    pub participant_count: u64,
    pub winner_count: u64,
    pub state: u8,
    pub commit_slot: u64,
    pub reveal_slot: u64,
    pub winner_root: [u8; 32],
}

/// Raw instruction data for fee verification.
struct RawInstruction {
    program_id: Pubkey,
    accounts: Vec<(Pubkey, bool)>,
    data: Vec<u8>,
}

/// Read the current instruction index from the instructions sysvar.
fn read_current_instruction_index(data: &[u8]) -> Result<u16> {
    require!(data.len() >= 2, GiveawayError::MissingFeeTransfer);
    let idx_bytes = &data[data.len() - 2..];
    Ok(u16::from_le_bytes(idx_bytes.try_into().unwrap()))
}

/// Read a specific instruction from the instructions sysvar.
fn read_instruction_at(data: &[u8], target_index: u16) -> Result<RawInstruction> {
    require!(data.len() >= 2, GiveawayError::MissingFeeTransfer);

    let num_instructions = u16::from_le_bytes(data[0..2].try_into().unwrap());
    require!(
        target_index < num_instructions,
        GiveawayError::MissingFeeTransfer
    );

    let offset_pos = 2 + (target_index as usize) * 2;
    require!(
        offset_pos + 2 <= data.len(),
        GiveawayError::MissingFeeTransfer
    );

    let instr_offset =
        u16::from_le_bytes(data[offset_pos..offset_pos + 2].try_into().unwrap()) as usize;
    require!(
        instr_offset <= data.len(),
        GiveawayError::MissingFeeTransfer
    );

    let mut cursor = instr_offset;

    require!(cursor + 2 <= data.len(), GiveawayError::MissingFeeTransfer);
    let num_accounts = u16::from_le_bytes(data[cursor..cursor + 2].try_into().unwrap());
    cursor += 2;

    let mut accounts = Vec::with_capacity(num_accounts as usize);
    for _ in 0..num_accounts {
        require!(
            cursor + 1 + 32 <= data.len(),
            GiveawayError::MissingFeeTransfer
        );
        let flags = data[cursor];
        cursor += 1;
        let pubkey = Pubkey::new_from_array(data[cursor..cursor + 32].try_into().unwrap());
        cursor += 32;
        accounts.push((pubkey, flags & 0b01 != 0));
    }

    require!(cursor + 32 <= data.len(), GiveawayError::MissingFeeTransfer);
    let program_id = Pubkey::new_from_array(data[cursor..cursor + 32].try_into().unwrap());
    cursor += 32;

    require!(cursor + 2 <= data.len(), GiveawayError::MissingFeeTransfer);
    let data_len = u16::from_le_bytes(data[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;

    require!(
        cursor + data_len <= data.len(),
        GiveawayError::MissingFeeTransfer
    );
    let ix_data = data[cursor..cursor + data_len].to_vec();

    Ok(RawInstruction {
        program_id,
        accounts,
        data: ix_data,
    })
}

/// Verify that a platform fee transfer occurred in the preceding instruction.
fn verify_fee_transfer(
    instructions_sysvar: &AccountInfo,
    expected_from: &Pubkey,
    expected_lamports: u64,
) -> Result<()> {
    let data = instructions_sysvar
        .try_borrow_data()
        .map_err(|_| error!(GiveawayError::MissingFeeTransfer))?;

    let current_index = read_current_instruction_index(&data)?;
    require!(current_index > 0, GiveawayError::MissingFeeTransfer);

    let prev_ix = read_instruction_at(&data, current_index - 1)?;

    require_keys_eq!(
        prev_ix.program_id,
        system_program_id::ID,
        GiveawayError::InvalidFeeTransferProgram
    );
    require!(
        prev_ix.data.len() == 12,
        GiveawayError::InvalidFeeTransferData
    );

    let tag = u32::from_le_bytes(prev_ix.data[0..4].try_into().unwrap());
    require!(tag == 2, GiveawayError::InvalidFeeTransferData);

    let lamports = u64::from_le_bytes(prev_ix.data[4..12].try_into().unwrap());
    require!(
        lamports == expected_lamports,
        GiveawayError::InvalidFeeTransferAmount
    );

    require!(
        prev_ix.accounts.len() >= 2,
        GiveawayError::InvalidFeeTransferData
    );

    let (from_pubkey, from_is_signer) = prev_ix.accounts[0];
    require!(from_is_signer, GiveawayError::InvalidFeeTransferFrom);
    require_keys_eq!(
        from_pubkey,
        *expected_from,
        GiveawayError::InvalidFeeTransferFrom
    );

    let (to_pubkey, _) = prev_ix.accounts[1];

    Ok(())
}

// PROGRAM INSTRUCTIONS

#[program]
pub mod provable_fairness {
    use super::*;

    /// Initialize a new user state account.
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        let user_state = &mut ctx.accounts.user_state;
        user_state.authority = ctx.accounts.authority.key();
        user_state.total_accounts = 0;

        msg!("User state initialized for: {}", user_state.authority);
        Ok(())
    }

    /// Create a new user giveaway account.
    pub fn create_user_account(ctx: Context<CreateUserAccount>) -> Result<()> {
        let user_state = &mut ctx.accounts.user_state;
        let user_account = &mut ctx.accounts.user_giveaways;

        require!(
            user_state.total_accounts < MAX_ACCOUNTS_PER_USER as u64,
            GiveawayError::MaxAccountsReached
        );

        user_account.authority = ctx.accounts.authority.key();
        user_account.account_index = user_state.total_accounts + 1;
        user_account.giveaways = Vec::new();
        user_account.giveaway_count = 0;

        user_state.total_accounts += 1;

        msg!("User account {} created", user_account.account_index);
        Ok(())
    }

    /// Create a new giveaway (state = created).
    pub fn create_giveaway(
        ctx: Context<CreateGiveaway>,
        account_index: u64,
        id: String,
        participant_root: [u8; 32],
        participant_count: u64,
        winner_count: u64,
        platform_fee: u64,
    ) -> Result<u64> {
        create_giveaway_core(
            &mut ctx.accounts.user_giveaways,
            &ctx.accounts.authority.key(),
            &ctx.accounts.instructions_sysvar.to_account_info(),
            account_index,
            &id,
            participant_root,
            participant_count,
            winner_count,
            platform_fee,
            0, // state: created
            0, // commit_slot: 0
            0, // reveal_slot: 0
        )
    }

    /// Create and commit a giveaway in a single transaction.
    pub fn create_and_commit_giveaway(
        ctx: Context<CreateAndCommitGiveaway>,
        account_index: u64,
        id: String,
        participant_root: [u8; 32],
        participant_count: u64,
        winner_count: u64,
        platform_fee: u64,
    ) -> Result<u64> {
        let current_slot = Clock::get()?.slot;

        create_giveaway_core(
            &mut ctx.accounts.user_giveaways,
            &ctx.accounts.authority.key(),
            &ctx.accounts.instructions_sysvar.to_account_info(),
            account_index,
            &id,
            participant_root,
            participant_count,
            winner_count,
            platform_fee,
            1,
            current_slot,
            current_slot + REVEAL_DELAY_SLOTS,
        )
    }

    /// Commit a draw (state: created -> committed).
    pub fn commit_draw(
        ctx: Context<CommitDraw>,
        account_index: u64,
        giveaway_index: u64,
    ) -> Result<()> {
        let user_account = &mut ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        let giveaway_data = user_account
            .giveaways
            .get_mut(giveaway_index as usize)
            .ok_or(GiveawayError::GiveawayNotFound)?;

        require!(
            giveaway_data.state == 0,
            GiveawayError::InvalidStateTransition
        );

        let current_slot = Clock::get()?.slot;

        giveaway_data.commit_slot = current_slot;
        giveaway_data.reveal_slot = current_slot + REVEAL_DELAY_SLOTS;
        giveaway_data.state = 1;

        msg!(
            "Draw committed for giveaway index {} at slot {}",
            giveaway_index,
            current_slot
        );

        Ok(())
    }

    /// Reveal winners (state: committed -> drawn).
    ///
    /// # Security Properties
    /// 1. **Unpredictable**: The slot hash at the commit slot cannot be known
    ///    in advance, making the randomness unpredictable.
    /// 2. **Verifiable**: Anyone can re-run the selection algorithm with the
    ///    same inputs and verify the winners.
    /// 3. **Tamper-proof**: The winner list is committed to the blockchain
    ///    and cannot be changed after the fact.
    pub fn reveal_draw(
        ctx: Context<RevealDraw>,
        account_index: u64,
        giveaway_index: u64,
        randomness: [u8; 32],
        winners: Vec<Winner>,
        winner_root: [u8; 32],
    ) -> Result<()> {
        let user_account = &mut ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        let giveaway_data = user_account
            .giveaways
            .get_mut(giveaway_index as usize)
            .ok_or(GiveawayError::GiveawayNotFound)?;

        require!(giveaway_data.state != 2, GiveawayError::AlreadyDrawn);
        require!(giveaway_data.state == 1, GiveawayError::NotCommitted);

        let current_slot = Clock::get()?.slot;

        require!(
            current_slot > giveaway_data.reveal_slot,
            GiveawayError::RevealTooEarly
        );
        require!(
            current_slot - giveaway_data.commit_slot <= MAX_REVEAL_WINDOW,
            GiveawayError::RevealWindowExpired
        );

        // Verify randomness from slot hash
        let target_hash = {
            let account_info = ctx.accounts.slot_hashes.to_account_info();
            let data = account_info.data.borrow();
            find_slot_hash(&data, giveaway_data.commit_slot)
                .ok_or(GiveawayError::SlotHashExpired)?
        };

        let expected_randomness = derive_randomness(&target_hash, &giveaway_data.participant_root);
        require!(
            randomness == expected_randomness,
            GiveawayError::InvalidRandomness
        );

        // Verify winner count matches
        let display_count = display_count(giveaway_data.winner_count);
        require!(
            winners.len() == display_count as usize,
            GiveawayError::WinnerCountMismatch
        );

        // Compute winner indices on-chain
        let winner_indices = select_winner_indices(
            &randomness,
            giveaway_data.participant_count,
            display_count as u64,
        );

        // Commit the winner root
        giveaway_data.state = 2;
        giveaway_data.winner_root = winner_root;

        emit!(WinnersRevealed {
            giveaway_index,
            randomness,
            winners,
            winner_root,
            winner_indices,
        });

        msg!(
            "Revealed {} winners for giveaway index {} at slot {}",
            giveaway_data.winner_count,
            giveaway_index,
            current_slot
        );

        Ok(())
    }

    /// Cancel a giveaway (state: created or committed -> cancelled).
    pub fn cancel_giveaway(
        ctx: Context<CancelGiveaway>,
        account_index: u64,
        giveaway_index: u64,
    ) -> Result<()> {
        let user_account = &mut ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        let giveaway_data = user_account
            .giveaways
            .get_mut(giveaway_index as usize)
            .ok_or(GiveawayError::GiveawayNotFound)?;

        require!(giveaway_data.state != 2, GiveawayError::AlreadyDrawn);

        giveaway_data.state = 3;

        msg!("Giveaway index {} cancelled", giveaway_index);
        Ok(())
    }

    /// Close a user account and reclaim rent.
    pub fn close_user_account(ctx: Context<CloseUserAccount>, account_index: u64) -> Result<()> {
        let user_account = &ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        for giveaway in user_account.giveaways.iter() {
            require!(
                giveaway.state == 2 || giveaway.state == 3,
                GiveawayError::AccountHasActiveGiveaways
            );
        }

        msg!(
            "Closing user account {} for {} ({} giveaways)",
            account_index,
            ctx.accounts.authority.key(),
            user_account.giveaways.len()
        );

        Ok(())
    }

    /// Get a specific giveaway from a user account.
    pub fn get_giveaway(
        ctx: Context<GetGiveaway>,
        account_index: u64,
        giveaway_index: u64,
    ) -> Result<GiveawayData> {
        let user_account = &ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        let giveaway_data = user_account
            .giveaways
            .get(giveaway_index as usize)
            .ok_or_else(|| {
                msg!(
                    "Giveaway index {} not found among {} entries",
                    giveaway_index,
                    user_account.giveaways.len()
                );
                GiveawayError::GiveawayNotFound
            })?;

        Ok(giveaway_data.clone())
    }

    /// Get all giveaways from a user account.
    pub fn get_all_giveaways(
        ctx: Context<GetGiveaway>,
        account_index: u64,
    ) -> Result<Vec<GiveawayData>> {
        let user_account = &ctx.accounts.user_giveaways;

        require!(
            user_account.account_index == account_index,
            GiveawayError::InvalidAccountIndex
        );

        Ok(user_account.giveaways.clone())
    }
}

// ACCOUNT CONTEXT STRUCTURES
#[derive(Accounts)]
pub struct InitializeUser<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8,
        seeds = [b"user_state", authority.key().as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateUserAccount<'info> {
    #[account(
        mut,
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        init,
        payer = authority,
        space = USER_ACCOUNT_INIT_SPACE,
        seeds = [b"user", authority.key().as_ref(), (user_state.total_accounts + 1).to_le_bytes().as_ref()],
        bump
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct CreateGiveaway<'info> {
    #[account(
        mut,
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority,
        realloc = user_giveaways.to_account_info().data_len() + GIVEAWAY_DATA_SIZE,
        realloc::payer = authority,
        realloc::zero = false,
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Treasury address verified via the `address` constraint.
    #[account(mut, address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: Instructions sysvar for fee verification.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct CreateAndCommitGiveaway<'info> {
    #[account(
        mut,
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority,
        realloc = user_giveaways.to_account_info().data_len() + GIVEAWAY_DATA_SIZE,
        realloc::payer = authority,
        realloc::zero = false,
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Treasury address verified via the `address` constraint.
    #[account(mut, address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
    /// CHECK: Instructions sysvar for fee verification.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct CommitDraw<'info> {
    #[account(
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct RevealDraw<'info> {
    #[account(seeds = [b"user_state", authority.key().as_ref()], bump)]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    /// CHECK: Original giveaway creator, used for PDA derivation.
    pub authority: UncheckedAccount<'info>,
    #[account(mut, address = KEEPER_PUBKEY)]
    pub payer: Signer<'info>,
    /// CHECK: Slot hashes sysvar for randomness.
    #[account(address = SLOT_HASHES_ID)]
    pub slot_hashes: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct CancelGiveaway<'info> {
    #[account(
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct CloseUserAccount<'info> {
    #[account(
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        mut,
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority,
        close = authority
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(account_index: u64)]
pub struct GetGiveaway<'info> {
    #[account(
        seeds = [b"user_state", authority.key().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_state: Account<'info, UserState>,
    #[account(
        seeds = [b"user", authority.key().as_ref(), account_index.to_le_bytes().as_ref()],
        bump,
        has_one = authority
    )]
    pub user_giveaways: Account<'info, UserGiveaways>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

// CORE GIVEAWAY CREATION LOGIC
fn create_giveaway_core(
    user_account: &mut Account<UserGiveaways>,
    authority: &Pubkey,
    instructions_sysvar: &AccountInfo,
    account_index: u64,
    id: &str,
    participant_root: [u8; 32],
    participant_count: u64,
    winner_count: u64,
    platform_fee: u64,
    state: u8,
    commit_slot: u64,
    reveal_slot: u64,
) -> Result<u64> {
    require!(
        user_account.account_index == account_index,
        GiveawayError::InvalidAccountIndex
    );

    require!(winner_count > 0, GiveawayError::InvalidWinnerCount);
    require!(
        winner_count <= participant_count,
        GiveawayError::InvalidWinnerCount
    );
    require!(
        participant_count <= MAX_PARTICIPANTS,
        GiveawayError::TooManyParticipants
    );
    require!(winner_count <= MAX_WINNERS, GiveawayError::TooManyWinners);
    require!(!id.is_empty(), GiveawayError::EmptyId);

    let expected_fee = calculate_platform_fee(participant_count);
    require!(platform_fee == expected_fee, GiveawayError::InvalidFee);

    if platform_fee > 0 {
        verify_fee_transfer(instructions_sysvar, authority, platform_fee)?;
    }

    let giveaway_data = GiveawayData {
        participant_root,
        participant_count,
        winner_count,
        state,
        commit_slot,
        reveal_slot,
        winner_root: [0u8; 32],
    };

    user_account.giveaways.push(giveaway_data);
    user_account.giveaway_count += 1;

    let new_index = (user_account.giveaways.len() - 1) as u64;

    msg!(
        "Giveaway {} created at index {}. Total: {}",
        id,
        new_index,
        user_account.giveaways.len()
    );

    Ok(new_index)
}

#[error_code]
pub enum GiveawayError {
    #[msg("Giveaway has already drawn winners")]
    AlreadyDrawn,
    #[msg("winner_count must be > 0 and <= participant_count")]
    InvalidWinnerCount,
    #[msg("Draw has already been committed")]
    AlreadyCommitted,
    #[msg("Giveaway has been cancelled")]
    AlreadyCancelled,
    #[msg("Draw must be committed before it can be revealed")]
    NotCommitted,
    #[msg("Cannot reveal before the committed slot has passed")]
    RevealTooEarly,
    #[msg("Committed slot's hash has expired")]
    SlotHashExpired,
    #[msg("Participant root mismatch")]
    InvalidParticipantRoot,
    #[msg("Too many participants (max 100,000)")]
    TooManyParticipants,
    #[msg("Too many winners (max 10,000)")]
    TooManyWinners,
    #[msg("Giveaway ID cannot be empty")]
    EmptyId,
    #[msg("Only the giveaway authority can perform this action")]
    Unauthorized,
    #[msg("Reveal window has expired (must reveal within 450 slots of commit)")]
    RevealWindowExpired,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Number of winners supplied doesn't match the expected display count")]
    WinnerCountMismatch,
    #[msg("Giveaway is not in a state that allows this operation")]
    InvalidStateTransition,
    #[msg("Invalid randomness derived from slot hash")]
    InvalidRandomness,
    #[msg("Giveaway not found in user account")]
    GiveawayNotFound,
    #[msg("Maximum accounts reached (100)")]
    MaxAccountsReached,
    #[msg("Invalid account index provided")]
    InvalidAccountIndex,
    #[msg("Account still has giveaways that haven't been drawn or cancelled")]
    AccountHasActiveGiveaways,
    #[msg("Invalid platform fee amount")]
    InvalidFee,
    #[msg("Expected a SystemProgram transfer instruction immediately before this one")]
    MissingFeeTransfer,
    #[msg("Preceding instruction is not owned by the System Program")]
    InvalidFeeTransferProgram,
    #[msg("Preceding instruction is not a valid Transfer")]
    InvalidFeeTransferData,
    #[msg("Preceding transfer amount doesn't match the required platform fee")]
    InvalidFeeTransferAmount,
    #[msg("Preceding transfer's source doesn't match the giveaway authority")]
    InvalidFeeTransferFrom,
    #[msg("Preceding transfer's destination doesn't match the treasury")]
    InvalidFeeTransferTo,
}

// TREASURY AND KEEPER ADDRESSES
/// The treasury address that receives platform fees.
/// This is a publicly verifiable address. Replace with your own treasury.
pub const TREASURY_PUBKEY: Pubkey = pubkey!("AoUY8D1M3X7fbgHy4XpgXqhpVSnLKgwfjnrC1ByAFXHU");

/// The keeper address authorized to call `reveal_draw`.
/// This is a publicly verifiable address. Replace with your own keeper.
pub const KEEPER_PUBKEY: Pubkey = pubkey!("HLxD5xGPBGv5X7nhK2agHvsP7Yu7tGmnPLmLdS8PcAqy");
