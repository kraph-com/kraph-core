//! Kraph Credits transfer-hook program.
//!
//! Sits behind the KCREDS_NOVALUE Token-2022 mint and gates every transfer
//! through a mutable on-chain allowlist. A transfer succeeds iff the
//! owner of either the source or destination token account is on the
//! allowlist; everything else reverts with `TransferNotAllowed`.
//!
//! Economic intent: operator is on the list, agents are not. Operator can
//! grant credits to agents (operator = source); agents can pay them back
//! to operator (operator = destination); agents cannot transfer credits
//! between each other. Allowlist is extensible (e.g. partner custody
//! wallets) under the admin authority set at init.
//!
//! Replace the `declare_id!` placeholder with the keypair-derived
//! pubkey after `anchor build` (or use `anchor keys sync`).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::{ExecuteInstruction, TransferHookInstruction};

declare_id!("11111111111111111111111111111111");

#[program]
pub mod kraph_credits_hook {
    use super::*;

    /// One-time init for the global allowlist PDA. Caller picks the admin
    /// authority (typically the operator's hot wallet) and seeds the list
    /// with one entry — usually the operator wallet itself — so the very
    /// first mint→operator transfer is permitted.
    pub fn initialize_allowlist(
        ctx: Context<InitializeAllowlist>,
        admin: Pubkey,
        first_entry: Pubkey,
    ) -> Result<()> {
        let allowlist = &mut ctx.accounts.allowlist;
        allowlist.admin = admin;
        allowlist.bump = ctx.bumps.allowlist;
        allowlist.entries = vec![first_entry];
        emit!(AllowlistInitialized { admin, first_entry });
        Ok(())
    }

    /// Append a wallet to the allowlist. Idempotent: re-adding is a no-op.
    pub fn add_to_allowlist(ctx: Context<AdminMutate>, wallet: Pubkey) -> Result<()> {
        let allowlist = &mut ctx.accounts.allowlist;
        require_keys_eq!(
            allowlist.admin,
            ctx.accounts.admin.key(),
            HookError::Unauthorized
        );
        require!(
            allowlist.entries.len() < Allowlist::MAX_ENTRIES,
            HookError::AllowlistFull
        );
        if !allowlist.entries.contains(&wallet) {
            allowlist.entries.push(wallet);
            emit!(AllowlistAdded { wallet });
        }
        Ok(())
    }

    /// Remove a wallet from the allowlist. Last entry is allowed to be
    /// removed — admins are trusted to not lock themselves out.
    pub fn remove_from_allowlist(ctx: Context<AdminMutate>, wallet: Pubkey) -> Result<()> {
        let allowlist = &mut ctx.accounts.allowlist;
        require_keys_eq!(
            allowlist.admin,
            ctx.accounts.admin.key(),
            HookError::Unauthorized
        );
        let before = allowlist.entries.len();
        allowlist.entries.retain(|w| w != &wallet);
        if allowlist.entries.len() != before {
            emit!(AllowlistRemoved { wallet });
        }
        Ok(())
    }

    /// Rotate the admin authority. Current admin must sign.
    pub fn transfer_admin(ctx: Context<AdminMutate>, new_admin: Pubkey) -> Result<()> {
        let allowlist = &mut ctx.accounts.allowlist;
        require_keys_eq!(
            allowlist.admin,
            ctx.accounts.admin.key(),
            HookError::Unauthorized
        );
        let old_admin = allowlist.admin;
        allowlist.admin = new_admin;
        emit!(AdminTransferred {
            old_admin,
            new_admin,
        });
        Ok(())
    }

    /// Create the per-mint ExtraAccountMetaList PDA. Token-2022 reads this
    /// to know which extra accounts to forward to `execute`. We register
    /// exactly one extra account: the global Allowlist PDA.
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        let extra_metas: Vec<ExtraAccountMeta> = vec![ExtraAccountMeta::new_with_seeds(
            &[Seed::Literal {
                bytes: b"allowlist".to_vec(),
            }],
            false, // is_signer
            false, // is_writable
        )?];

        let account_size = ExtraAccountMetaList::size_of(extra_metas.len())?;

        let payer = &ctx.accounts.payer;
        let extra_meta_list = &ctx.accounts.extra_account_meta_list;
        let system_program = &ctx.accounts.system_program;

        // Fund + allocate the PDA. We sign with the PDA seeds because the
        // account is owned by this program after allocation.
        let mint_key = ctx.accounts.mint.key();
        let bump = ctx.bumps.extra_account_meta_list;
        let signer_seeds: &[&[&[u8]]] = &[&[b"extra-account-metas", mint_key.as_ref(), &[bump]]];

        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(account_size as usize);

        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: payer.to_account_info(),
                    to: extra_meta_list.to_account_info(),
                },
                signer_seeds,
            ),
            lamports,
            account_size as u64,
            &crate::ID,
        )?;

        let mut data = extra_meta_list.try_borrow_mut_data()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, &extra_metas)?;

        Ok(())
    }

    /// The actual transfer-hook handler. Invoked by Token-2022 on every
    /// transfer of the gated mint.
    ///
    /// Checks that either the source-token owner or the destination-token
    /// owner is on the allowlist. If neither is, the transfer is rejected
    /// and Token-2022 reverts the whole transaction.
    pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
        let source_owner = ctx.accounts.source_token.owner;
        let destination_owner = ctx.accounts.destination_token.owner;
        let allowlist = &ctx.accounts.allowlist;

        let allowed = allowlist.entries.contains(&source_owner)
            || allowlist.entries.contains(&destination_owner);

        require!(allowed, HookError::TransferNotAllowed);
        Ok(())
    }

    /// Anchor's instruction discriminators don't match the SPL transfer-
    /// hook interface's `Execute` discriminator. Token-2022 invokes the
    /// hook using the interface's discriminator, so we route it here.
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = TransferHookInstruction::unpack(data)?;
        match instruction {
            TransferHookInstruction::Execute { amount } => {
                let amount_bytes = amount.to_le_bytes();
                __private::__global::transfer_hook(program_id, accounts, &amount_bytes)
            }
            _ => Err(ProgramError::InvalidInstructionData.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct InitializeAllowlist<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = Allowlist::SPACE,
        seeds = [b"allowlist"],
        bump,
    )]
    pub allowlist: Account<'info, Allowlist>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminMutate<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"allowlist"], bump = allowlist.bump)]
    pub allowlist: Account<'info, Allowlist>,
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: initialized by this instruction.
    #[account(
        mut,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    pub mint: InterfaceAccount<'info, Mint>,
    pub system_program: Program<'info, System>,
}

/// Account layout that Token-2022 supplies when calling the hook.
/// The fixed prefix (0..=4) is dictated by the SPL Transfer Hook
/// interface; index 5 is our extra account (the Allowlist PDA).
#[derive(Accounts)]
pub struct TransferHook<'info> {
    #[account(token::mint = mint)]
    pub source_token: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: source-account authority. Validated by Token-2022.
    pub owner: UncheckedAccount<'info>,
    /// CHECK: ExtraAccountMetaList PDA.
    #[account(
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    #[account(seeds = [b"allowlist"], bump = allowlist.bump)]
    pub allowlist: Account<'info, Allowlist>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[account]
pub struct Allowlist {
    pub admin: Pubkey,
    pub bump: u8,
    pub entries: Vec<Pubkey>,
}

impl Allowlist {
    /// 64 entries is plenty for a hub-and-spoke setup (operator +
    /// custody providers + treasuries + partners). Costs about 2.1 KB
    /// of rent on-chain. Bumping later requires a realloc instruction.
    pub const MAX_ENTRIES: usize = 64;
    pub const SPACE: usize = 8  // discriminator
        + 32                    // admin
        + 1                     // bump
        + 4                     // Vec length prefix
        + (32 * Self::MAX_ENTRIES);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct AllowlistInitialized {
    pub admin: Pubkey,
    pub first_entry: Pubkey,
}

#[event]
pub struct AllowlistAdded {
    pub wallet: Pubkey,
}

#[event]
pub struct AllowlistRemoved {
    pub wallet: Pubkey,
}

#[event]
pub struct AdminTransferred {
    pub old_admin: Pubkey,
    pub new_admin: Pubkey,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum HookError {
    #[msg("Transfer not allowed: neither source nor destination is on the allowlist")]
    TransferNotAllowed,
    #[msg("Unauthorized: signer is not the allowlist admin")]
    Unauthorized,
    #[msg("Allowlist is full")]
    AllowlistFull,
}
