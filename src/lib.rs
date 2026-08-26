// Provable Fairness System - Core Anchor Program

#![allow(unexpected_cfgs)]
#![allow(unknown_lints)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program as system_program_id;

pub mod shared;
pub use shared::{
    calculate_platform_fee, compute_merkle_root, derive_randomness, display_count, find_slot_hash,
    select_winner_indices, verify_winner_indices, MAX_DISPLAYED_WINNERS, MAX_PARTICIPANTS,
    MAX_REVEAL_WINDOW, MAX_WINNERS, REVEAL_DELAY_SLOTS,
};

declare_id!("EGJ9Y7baCg7MrPatH8myHmmKWqFHDPMeFCSUw9vwdnr3");

pub const GIVEAWAY_DATA_SIZE: usize = 97;
pub const USER_ACCOUNT_INIT_SPACE: usize = 60 + (5 * GIVEAWAY_DATA_SIZE);
pub const MAX_ACCOUNTS_PER_USER: usize = 100;
pub const SLOT_HASHES_ID: Pubkey = pubkey!("SysvarS1otHashes111111111111111111111111111");
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");
pub const TREASURY_PUBKEY: Pubkey = pubkey!("AoUY8D1M3X7fbgHy4XpgXqhpVSnLKgwfjnrC1ByAFXHU");
pub const KEEPER_PUBKEY: Pubkey = pubkey!("HLxD5xGPBGv5X7nhK2agHvsP7Yu7tGmnPLmLdS8PcAqy");

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

#[account]
pub struct UserState {
    pub authority: Pubkey,
    pub total_accounts: u64,
}

#[account]
pub struct UserGiveaways {
    pub authority: Pubkey,
    pub account_index: u64,
    pub giveaways: Vec<GiveawayData>,
    pub giveaway_count: u64,
}

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

struct RawInstruction {
    program_id: Pubkey,
    accounts: Vec<(Pubkey, bool)>,
    data: Vec<u8>,
}

fn read_current_instruction_index(data: &[u8]) -> Result<u16> {
    require!(data.len() >= 2, GiveawayError::MissingFeeTransfer);
    let idx_bytes = &data[data.len() - 2..];
    Ok(u16::from_le_bytes(idx_bytes.try_into().unwrap()))
}

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

    let (_to_pubkey, _) = prev_ix.accounts[1];

    Ok(())
}

#[program]
pub mod provable_fairness {
    use super::*;

    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        let user_state = &mut ctx.accounts.user_state;
        user_state.authority = ctx.accounts.authority.key();
        user_state.total_accounts = 0;
        msg!("User state initialized for: {}", user_state.authority);
        Ok(())
    }

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
            0,
            0,
            0,
        )
    }

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

        let display_count = display_count(giveaway_data.winner_count);
        require!(
            winners.len() == display_count as usize,
            GiveawayError::WinnerCountMismatch
        );

        let winner_indices = select_winner_indices(
            &randomness,
            giveaway_data.participant_count,
            display_count as u64,
        );

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
    #[account(mut, address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
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
    #[account(mut, address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
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
    pub authority: UncheckedAccount<'info>,
    #[account(mut, address = KEEPER_PUBKEY)]
    pub payer: Signer<'info>,
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
