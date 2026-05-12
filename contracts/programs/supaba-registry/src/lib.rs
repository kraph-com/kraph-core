use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_lang::Discriminator;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("9B6JGBf3djjquA5mx9VsnTb9GTyMMjL1c4F2wpY5W9dv");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_ENDPOINT_LEN: usize = 256;
const MAX_REGION_LEN: usize = 32;
const MAX_REPLICA_NODES: usize = 3;
const MAX_ENCRYPTED_DEK_LEN: usize = 128;

// Account sizes (8 byte discriminator included)
const NODE_RECORD_SIZE: usize = 8  // discriminator
    + 32                           // operator
    + (4 + MAX_ENDPOINT_LEN)       // endpoint (String)
    + 1                            // capacity
    + 1                            // active_instances
    + 8                            // stake
    + 8                            // registered_at
    + 8                            // last_heartbeat
    + 1                            // status (enum)
    + (4 + MAX_REGION_LEN)         // region (String)
    + 1;                           // bump

const INSTANCE_RECORD_SIZE: usize = 8  // discriminator
    + 32                               // agent
    + 16                               // instance_id
    + 32                               // primary_node
    + (4 + 32 * MAX_REPLICA_NODES)     // replica_nodes (Vec<Pubkey>)
    + (4 + MAX_ENCRYPTED_DEK_LEN)      // encrypted_dek (Vec<u8>)
    + 32                               // merkle_root
    + 1                                // status (enum)
    + 8                                // created_at
    + 8                                // updated_at
    + 1;                               // bump

const PAYMENT_ESCROW_SIZE: usize = 8  // discriminator
    + 32                               // agent
    + 16                               // instance_id
    + 8                                // deposited
    + 8                                // distributed
    + 8                                // rate_per_hour
    + 8                                // last_distribution_at
    + 1;                               // bump

const NETWORK_CONFIG_SIZE: usize = 8  // discriminator
    + 32                               // authority
    + 8                                // min_stake
    + 8                                // default_rate_per_hour
    + 32                               // usdc_mint
    + 8                                // deregistration_cooldown
    + 1                                // slash_percentage
    + 1;                               // bump

// ---------------------------------------------------------------------------
// Program
// ---------------------------------------------------------------------------

#[program]
pub mod supaba_registry {
    use super::*;

    // 1. initialize_config
    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        min_stake: u64,
        default_rate: u64,
        usdc_mint: Pubkey,
        cooldown: i64,
        slash_pct: u8,
    ) -> Result<()> {
        require!(slash_pct <= 100, SupabaError::InvalidSlashPercentage);
        require!(cooldown >= 0, SupabaError::InvalidCooldown);

        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.min_stake = min_stake;
        config.default_rate_per_hour = default_rate;
        config.usdc_mint = usdc_mint;
        config.deregistration_cooldown = cooldown;
        config.slash_percentage = slash_pct;
        config.bump = ctx.bumps.config;

        emit!(ConfigInitialized {
            authority: config.authority,
            min_stake,
            default_rate,
            usdc_mint,
        });

        Ok(())
    }

    // 2. register_node
    pub fn register_node(
        ctx: Context<RegisterNode>,
        endpoint: String,
        capacity: u8,
        region: String,
    ) -> Result<()> {
        require!(endpoint.len() <= MAX_ENDPOINT_LEN, SupabaError::EndpointTooLong);
        require!(region.len() <= MAX_REGION_LEN, SupabaError::RegionTooLong);
        require!(capacity > 0, SupabaError::InvalidCapacity);

        let config = &ctx.accounts.config;
        let stake_amount = config.min_stake;

        // Transfer SOL from operator to the node PDA
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.operator.to_account_info(),
                    to: ctx.accounts.node.to_account_info(),
                },
            ),
            stake_amount,
        )?;

        let clock = Clock::get()?;
        let node = &mut ctx.accounts.node;
        node.operator = ctx.accounts.operator.key();
        node.endpoint = endpoint;
        node.capacity = capacity;
        node.active_instances = 0;
        node.stake = stake_amount;
        node.registered_at = clock.unix_timestamp;
        node.last_heartbeat = clock.unix_timestamp;
        node.status = NodeStatus::Active;
        node.region = region;
        node.bump = ctx.bumps.node;

        emit!(NodeRegistered {
            operator: node.operator,
            endpoint: node.endpoint.clone(),
            capacity,
            stake: stake_amount,
        });

        Ok(())
    }

    // 3. update_node
    pub fn update_node(
        ctx: Context<UpdateNode>,
        endpoint: Option<String>,
        capacity: Option<u8>,
        region: Option<String>,
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;
        require!(node.status == NodeStatus::Active, SupabaError::NodeNotActive);

        if let Some(ep) = endpoint {
            require!(ep.len() <= MAX_ENDPOINT_LEN, SupabaError::EndpointTooLong);
            node.endpoint = ep;
        }
        if let Some(cap) = capacity {
            require!(cap > 0, SupabaError::InvalidCapacity);
            require!(cap >= node.active_instances, SupabaError::CapacityBelowActive);
            node.capacity = cap;
        }
        if let Some(reg) = region {
            require!(reg.len() <= MAX_REGION_LEN, SupabaError::RegionTooLong);
            node.region = reg;
        }

        emit!(NodeUpdated {
            operator: node.operator,
        });

        Ok(())
    }

    // 4. heartbeat
    pub fn heartbeat(ctx: Context<Heartbeat>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        require!(node.status == NodeStatus::Active, SupabaError::NodeNotActive);

        let clock = Clock::get()?;
        node.last_heartbeat = clock.unix_timestamp;

        emit!(HeartbeatRecorded {
            operator: node.operator,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // 5. deregister_node
    pub fn deregister_node(ctx: Context<DeregisterNode>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        require!(
            node.status == NodeStatus::Active,
            SupabaError::NodeNotActive
        );

        let clock = Clock::get()?;
        node.status = NodeStatus::Deregistering;
        node.last_heartbeat = clock.unix_timestamp; // record deregistration time

        emit!(NodeDeregistering {
            operator: node.operator,
            deregistering_at: clock.unix_timestamp,
        });

        Ok(())
    }

    // 6. claim_stake
    pub fn claim_stake(ctx: Context<ClaimStake>) -> Result<()> {
        let node = &mut ctx.accounts.node;
        require!(
            node.status == NodeStatus::Deregistering,
            SupabaError::NodeNotDeregistering
        );
        require!(
            node.active_instances == 0,
            SupabaError::ActiveInstancesRemaining
        );

        let clock = Clock::get()?;
        let config = &ctx.accounts.config;
        // last_heartbeat stores the deregistration timestamp
        let elapsed = clock.unix_timestamp.saturating_sub(node.last_heartbeat);
        require!(
            elapsed >= config.deregistration_cooldown,
            SupabaError::CooldownNotElapsed
        );

        let stake_amount = node.stake;
        node.stake = 0;
        node.status = NodeStatus::Deregistered;

        // Transfer SOL from node PDA back to operator
        let node_info = node.to_account_info();
        let operator_info = ctx.accounts.operator.to_account_info();
        **node_info.try_borrow_mut_lamports()? = node_info
            .lamports()
            .checked_sub(stake_amount)
            .ok_or(SupabaError::InsufficientFunds)?;
        **operator_info.try_borrow_mut_lamports()? = operator_info
            .lamports()
            .checked_add(stake_amount)
            .ok_or(SupabaError::Overflow)?;

        emit!(StakeClaimed {
            operator: node.operator,
            amount: stake_amount,
        });

        Ok(())
    }

    // 7. allocate_instance
    pub fn allocate_instance(
        ctx: Context<AllocateInstance>,
        instance_id: [u8; 16],
        replica_nodes: Vec<Pubkey>,
        encrypted_dek: Vec<u8>,
    ) -> Result<()> {
        require!(replica_nodes.len() <= MAX_REPLICA_NODES, SupabaError::TooManyReplicas);
        require!(encrypted_dek.len() <= MAX_ENCRYPTED_DEK_LEN, SupabaError::DekTooLong);

        let primary = &mut ctx.accounts.primary_node;
        require!(primary.status == NodeStatus::Active, SupabaError::NodeNotActive);
        require!(
            primary.active_instances < primary.capacity,
            SupabaError::NodeAtCapacity
        );

        // Validate replica nodes via remaining accounts
        let remaining = &ctx.remaining_accounts;
        require!(
            remaining.len() == replica_nodes.len(),
            SupabaError::ReplicaAccountMismatch
        );
        for (i, replica_key) in replica_nodes.iter().enumerate() {
            require!(
                remaining[i].key() == *replica_key,
                SupabaError::ReplicaAccountMismatch
            );
            // Verify owner is this program
            require!(
                remaining[i].owner == &crate::ID,
                SupabaError::InvalidReplicaNode
            );
            let data = remaining[i].try_borrow_data()?;
            // Check discriminator matches NodeRecord
            require!(data.len() > 8, SupabaError::InvalidReplicaNode);
            let expected_disc = NodeRecord::DISCRIMINATOR;
            require!(
                data[..8] == *expected_disc,
                SupabaError::InvalidReplicaNode
            );
            let mut slice: &[u8] = &data[8..];
            let replica_node = NodeRecord::deserialize(&mut slice)
                .map_err(|_| SupabaError::InvalidReplicaNode)?;
            require!(
                replica_node.status == NodeStatus::Active,
                SupabaError::ReplicaNodeNotActive
            );
        }

        primary.active_instances = primary
            .active_instances
            .checked_add(1)
            .ok_or(SupabaError::Overflow)?;

        let clock = Clock::get()?;
        let instance = &mut ctx.accounts.instance;
        instance.agent = ctx.accounts.agent.key();
        instance.instance_id = instance_id;
        instance.primary_node = primary.key();
        instance.replica_nodes = replica_nodes;
        instance.encrypted_dek = encrypted_dek;
        instance.merkle_root = [0u8; 32];
        instance.status = InstanceStatus::Provisioning;
        instance.created_at = clock.unix_timestamp;
        instance.updated_at = clock.unix_timestamp;
        instance.bump = ctx.bumps.instance;

        emit!(InstanceAllocated {
            agent: instance.agent,
            instance_id,
            primary_node: instance.primary_node,
        });

        Ok(())
    }

    // 8. activate_instance
    pub fn activate_instance(ctx: Context<ActivateInstance>, _instance_id: [u8; 16]) -> Result<()> {
        let instance = &mut ctx.accounts.instance;
        require!(
            instance.status == InstanceStatus::Provisioning,
            SupabaError::InvalidStatusTransition
        );

        let clock = Clock::get()?;
        instance.status = InstanceStatus::Active;
        instance.updated_at = clock.unix_timestamp;

        emit!(InstanceActivated {
            instance_id: instance.instance_id,
        });

        Ok(())
    }

    // 9. update_instance_status
    pub fn update_instance_status(
        ctx: Context<UpdateInstanceStatus>,
        _instance_id: [u8; 16],
        new_status: InstanceStatus,
    ) -> Result<()> {
        let instance = &mut ctx.accounts.instance;
        let signer = ctx.accounts.signer.key();

        let is_agent = signer == instance.agent;
        let is_node_operator = signer == ctx.accounts.primary_node.operator;

        match new_status {
            InstanceStatus::Suspended => {
                require!(
                    is_agent || is_node_operator,
                    SupabaError::Unauthorized
                );
            }
            InstanceStatus::Destroyed => {
                require!(is_agent, SupabaError::Unauthorized);
            }
            InstanceStatus::Migrating => {
                require!(is_node_operator, SupabaError::Unauthorized);
            }
            _ => {
                return Err(SupabaError::InvalidStatusTransition.into());
            }
        }

        let clock = Clock::get()?;
        instance.status = new_status;
        instance.updated_at = clock.unix_timestamp;

        emit!(InstanceStatusUpdated {
            instance_id: instance.instance_id,
        });

        Ok(())
    }

    // 10. destroy_instance
    pub fn destroy_instance(ctx: Context<DestroyInstance>, _instance_id: [u8; 16]) -> Result<()> {
        let instance = &mut ctx.accounts.instance;
        let primary = &mut ctx.accounts.primary_node;

        let clock = Clock::get()?;
        instance.status = InstanceStatus::Destroyed;
        instance.updated_at = clock.unix_timestamp;

        primary.active_instances = primary
            .active_instances
            .checked_sub(1)
            .ok_or(SupabaError::Overflow)?;

        // Return remaining escrow funds to agent if escrow exists
        let escrow_deposited = ctx.accounts.escrow.deposited;
        let escrow_distributed = ctx.accounts.escrow.distributed;
        let escrow_bump = ctx.accounts.escrow.bump;
        let remaining = escrow_deposited
            .checked_sub(escrow_distributed)
            .ok_or(SupabaError::Overflow)?;

        if remaining > 0 {
            let instance_id = instance.instance_id;
            let agent_key = instance.agent;
            let seeds: &[&[u8]] = &[
                b"escrow",
                agent_key.as_ref(),
                instance_id.as_ref(),
                &[escrow_bump],
            ];
            let signer_seeds = &[seeds];

            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.escrow_token_account.to_account_info(),
                        to: ctx.accounts.agent_token_account.to_account_info(),
                        authority: ctx.accounts.escrow.to_account_info(),
                    },
                    signer_seeds,
                ),
                remaining,
            )?;
        }

        emit!(InstanceDestroyed {
            instance_id: instance.instance_id,
            agent: instance.agent,
        });

        Ok(())
    }

    // 11. deposit_payment
    pub fn deposit_payment(
        ctx: Context<DepositPayment>,
        instance_id: [u8; 16],
        amount: u64,
    ) -> Result<()> {
        require!(amount > 0, SupabaError::InvalidAmount);

        // Transfer USDC from agent to escrow token account
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.agent_token_account.to_account_info(),
                    to: ctx.accounts.escrow_token_account.to_account_info(),
                    authority: ctx.accounts.agent.to_account_info(),
                },
            ),
            amount,
        )?;

        let escrow = &mut ctx.accounts.escrow;
        let clock = Clock::get()?;

        // Initialize escrow fields if first deposit (deposited == 0 and distributed == 0)
        if escrow.deposited == 0 && escrow.distributed == 0 && escrow.rate_per_hour == 0 {
            escrow.agent = ctx.accounts.agent.key();
            escrow.instance_id = instance_id;
            escrow.rate_per_hour = ctx.accounts.config.default_rate_per_hour;
            escrow.last_distribution_at = clock.unix_timestamp;
            escrow.bump = ctx.bumps.escrow;
        }

        escrow.deposited = escrow
            .deposited
            .checked_add(amount)
            .ok_or(SupabaError::Overflow)?;

        emit!(PaymentDeposited {
            agent: escrow.agent,
            instance_id,
            amount,
            total_deposited: escrow.deposited,
        });

        Ok(())
    }

    // 12. distribute_payment (permissionless crank)
    pub fn distribute_payment<'info>(
        ctx: Context<'_, '_, 'info, 'info, DistributePayment<'info>>,
        _instance_id: [u8; 16],
    ) -> Result<()> {
        let clock = Clock::get()?;

        // Read escrow values into locals before any mutable borrow
        let escrow_agent = ctx.accounts.escrow.agent;
        let escrow_instance_id = ctx.accounts.escrow.instance_id;
        let escrow_bump = ctx.accounts.escrow.bump;
        let escrow_rate = ctx.accounts.escrow.rate_per_hour;
        let escrow_last_dist = ctx.accounts.escrow.last_distribution_at;
        let escrow_deposited = ctx.accounts.escrow.deposited;
        let escrow_distributed = ctx.accounts.escrow.distributed;

        let elapsed_secs = clock
            .unix_timestamp
            .checked_sub(escrow_last_dist)
            .ok_or(SupabaError::Overflow)? as u64;

        // Calculate payment: (elapsed_secs * rate_per_hour) / 3600
        let payment = elapsed_secs
            .checked_mul(escrow_rate)
            .ok_or(SupabaError::Overflow)?
            .checked_div(3600)
            .ok_or(SupabaError::Overflow)?;

        let remaining = escrow_deposited
            .checked_sub(escrow_distributed)
            .ok_or(SupabaError::Overflow)?;

        // Cap at remaining balance
        let actual_payment = payment.min(remaining);

        if actual_payment == 0 {
            return Ok(());
        }

        // Calculate shares: 70% primary, 15% each replica (up to 2 replicas get 15%)
        // If fewer than 2 replicas, remainder stays in escrow
        let primary_share = actual_payment
            .checked_mul(70)
            .ok_or(SupabaError::Overflow)?
            .checked_div(100)
            .ok_or(SupabaError::Overflow)?;

        let replica_share_each = actual_payment
            .checked_mul(15)
            .ok_or(SupabaError::Overflow)?
            .checked_div(100)
            .ok_or(SupabaError::Overflow)?;

        let seeds: &[&[u8]] = &[
            b"escrow",
            escrow_agent.as_ref(),
            escrow_instance_id.as_ref(),
            &[escrow_bump],
        ];
        let signer_seeds = &[seeds];

        // Pay primary node operator
        let mut total_distributed: u64 = 0;
        if primary_share > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.escrow_token_account.to_account_info(),
                        to: ctx.accounts.primary_operator_token_account.to_account_info(),
                        authority: ctx.accounts.escrow.to_account_info(),
                    },
                    signer_seeds,
                ),
                primary_share,
            )?;
            total_distributed = total_distributed
                .checked_add(primary_share)
                .ok_or(SupabaError::Overflow)?;
        }

        // Pay replica operators via remaining_accounts (pairs of: replica_operator_token_account)
        let replica_count = ctx.accounts.instance.replica_nodes.len().min(MAX_REPLICA_NODES);
        let remaining_accounts = &ctx.remaining_accounts;
        for i in 0..replica_count {
            if i >= remaining_accounts.len() {
                break;
            }
            if replica_share_each > 0 {
                token::transfer(
                    CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.escrow_token_account.to_account_info(),
                            to: remaining_accounts[i].to_account_info(),
                            authority: ctx.accounts.escrow.to_account_info(),
                        },
                        signer_seeds,
                    ),
                    replica_share_each,
                )?;
                total_distributed = total_distributed
                    .checked_add(replica_share_each)
                    .ok_or(SupabaError::Overflow)?;
            }
        }

        let escrow = &mut ctx.accounts.escrow;
        let instance = &mut ctx.accounts.instance;

        escrow.distributed = escrow_distributed
            .checked_add(total_distributed)
            .ok_or(SupabaError::Overflow)?;
        escrow.last_distribution_at = clock.unix_timestamp;

        // Check if balance is exhausted
        let new_remaining = escrow
            .deposited
            .checked_sub(escrow.distributed)
            .ok_or(SupabaError::Overflow)?;
        if new_remaining == 0 {
            instance.status = InstanceStatus::Suspended;
            instance.updated_at = clock.unix_timestamp;
        }

        emit!(PaymentDistributed {
            instance_id: instance.instance_id,
            amount: total_distributed,
            remaining: new_remaining,
        });

        Ok(())
    }

    // 13. commit_merkle_root
    pub fn commit_merkle_root(
        ctx: Context<CommitMerkleRoot>,
        _instance_id: [u8; 16],
        root: [u8; 32],
    ) -> Result<()> {
        let instance = &mut ctx.accounts.instance;
        require!(
            instance.status == InstanceStatus::Active,
            SupabaError::InstanceNotActive
        );

        let clock = Clock::get()?;
        instance.merkle_root = root;
        instance.updated_at = clock.unix_timestamp;

        emit!(MerkleRootCommitted {
            instance_id: instance.instance_id,
            root,
        });

        Ok(())
    }

    // 14. slash_node
    pub fn slash_node(
        ctx: Context<SlashNode>,
        _instance_id: [u8; 16],
        proof_type: SlashProofType,
    ) -> Result<()> {
        let node = &mut ctx.accounts.node;
        let config = &ctx.accounts.config;

        let slash_amount = node
            .stake
            .checked_mul(config.slash_percentage as u64)
            .ok_or(SupabaError::Overflow)?
            .checked_div(100)
            .ok_or(SupabaError::Overflow)?;

        node.stake = node
            .stake
            .checked_sub(slash_amount)
            .ok_or(SupabaError::Overflow)?;
        node.status = NodeStatus::Suspended;

        // Transfer slashed SOL from node PDA to authority (treasury)
        let node_info = node.to_account_info();
        let treasury_info = ctx.accounts.authority.to_account_info();
        **node_info.try_borrow_mut_lamports()? = node_info
            .lamports()
            .checked_sub(slash_amount)
            .ok_or(SupabaError::InsufficientFunds)?;
        **treasury_info.try_borrow_mut_lamports()? = treasury_info
            .lamports()
            .checked_add(slash_amount)
            .ok_or(SupabaError::Overflow)?;

        emit!(NodeSlashed {
            operator: node.operator,
            slash_amount,
            proof_type,
        });

        Ok(())
    }

    // 15. migrate_instance
    pub fn migrate_instance(
        ctx: Context<MigrateInstance>,
        _instance_id: [u8; 16],
    ) -> Result<()> {
        let instance = &mut ctx.accounts.instance;
        let old_primary = &mut ctx.accounts.old_primary;
        let new_primary = &mut ctx.accounts.new_primary;

        require!(
            new_primary.status == NodeStatus::Active,
            SupabaError::NodeNotActive
        );
        require!(
            new_primary.active_instances < new_primary.capacity,
            SupabaError::NodeAtCapacity
        );

        old_primary.active_instances = old_primary
            .active_instances
            .checked_sub(1)
            .ok_or(SupabaError::Overflow)?;

        new_primary.active_instances = new_primary
            .active_instances
            .checked_add(1)
            .ok_or(SupabaError::Overflow)?;

        let clock = Clock::get()?;
        instance.primary_node = new_primary.key();
        instance.status = InstanceStatus::Migrating;
        instance.updated_at = clock.unix_timestamp;

        emit!(InstanceMigrated {
            instance_id: instance.instance_id,
            old_primary: old_primary.key(),
            new_primary: new_primary.key(),
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum NodeStatus {
    Active,
    Suspended,
    Deregistering,
    Deregistered,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum InstanceStatus {
    Provisioning,
    Active,
    Migrating,
    Suspended,
    Destroyed,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum SlashProofType {
    Downtime,
    IntegrityViolation,
    Other,
}

// ---------------------------------------------------------------------------
// Account structs
// ---------------------------------------------------------------------------

#[account]
pub struct NetworkConfig {
    pub authority: Pubkey,
    pub min_stake: u64,
    pub default_rate_per_hour: u64,
    pub usdc_mint: Pubkey,
    pub deregistration_cooldown: i64,
    pub slash_percentage: u8,
    pub bump: u8,
}

#[account]
pub struct NodeRecord {
    pub operator: Pubkey,
    pub endpoint: String,
    pub capacity: u8,
    pub active_instances: u8,
    pub stake: u64,
    pub registered_at: i64,
    pub last_heartbeat: i64,
    pub status: NodeStatus,
    pub region: String,
    pub bump: u8,
}

#[account]
pub struct InstanceRecord {
    pub agent: Pubkey,
    pub instance_id: [u8; 16],
    pub primary_node: Pubkey,
    pub replica_nodes: Vec<Pubkey>,
    pub encrypted_dek: Vec<u8>,
    pub merkle_root: [u8; 32],
    pub status: InstanceStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub bump: u8,
}

#[account]
pub struct PaymentEscrow {
    pub agent: Pubkey,
    pub instance_id: [u8; 16],
    pub deposited: u64,
    pub distributed: u64,
    pub rate_per_hour: u64,
    pub last_distribution_at: i64,
    pub bump: u8,
}

// ---------------------------------------------------------------------------
// Instruction account contexts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = authority,
        space = NETWORK_CONFIG_SIZE,
        seeds = [b"config"],
        bump,
    )]
    pub config: Account<'info, NetworkConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(endpoint: String, capacity: u8, region: String)]
pub struct RegisterNode<'info> {
    #[account(
        init,
        payer = operator,
        space = NODE_RECORD_SIZE,
        seeds = [b"node", operator.key().as_ref()],
        bump,
    )]
    pub node: Account<'info, NodeRecord>,

    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NetworkConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateNode<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node.bump,
        constraint = node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub node: Account<'info, NodeRecord>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct Heartbeat<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node.bump,
        constraint = node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub node: Account<'info, NodeRecord>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct DeregisterNode<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node.bump,
        constraint = node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub node: Account<'info, NodeRecord>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimStake<'info> {
    #[account(
        mut,
        seeds = [b"node", operator.key().as_ref()],
        bump = node.bump,
        constraint = node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub node: Account<'info, NodeRecord>,

    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
    )]
    pub config: Account<'info, NetworkConfig>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct AllocateInstance<'info> {
    #[account(
        init,
        payer = agent,
        space = INSTANCE_RECORD_SIZE,
        seeds = [b"instance", agent.key().as_ref(), instance_id.as_ref()],
        bump,
    )]
    pub instance: Account<'info, InstanceRecord>,

    #[account(
        mut,
        constraint = primary_node.status == NodeStatus::Active @ SupabaError::NodeNotActive,
    )]
    pub primary_node: Account<'info, NodeRecord>,

    #[account(mut)]
    pub agent: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct ActivateInstance<'info> {
    #[account(
        mut,
        seeds = [b"instance", instance.agent.as_ref(), instance_id.as_ref()],
        bump = instance.bump,
    )]
    pub instance: Account<'info, InstanceRecord>,

    /// The primary node record to verify the signer is the operator
    #[account(
        constraint = primary_node.key() == instance.primary_node @ SupabaError::Unauthorized,
        constraint = primary_node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub primary_node: Account<'info, NodeRecord>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct UpdateInstanceStatus<'info> {
    #[account(
        mut,
        seeds = [b"instance", instance.agent.as_ref(), instance_id.as_ref()],
        bump = instance.bump,
    )]
    pub instance: Account<'info, InstanceRecord>,

    #[account(
        constraint = primary_node.key() == instance.primary_node @ SupabaError::Unauthorized,
    )]
    pub primary_node: Account<'info, NodeRecord>,

    pub signer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct DestroyInstance<'info> {
    #[account(
        mut,
        seeds = [b"instance", agent.key().as_ref(), instance_id.as_ref()],
        bump = instance.bump,
        constraint = instance.agent == agent.key() @ SupabaError::Unauthorized,
    )]
    pub instance: Account<'info, InstanceRecord>,

    #[account(
        mut,
        constraint = primary_node.key() == instance.primary_node @ SupabaError::Unauthorized,
    )]
    pub primary_node: Account<'info, NodeRecord>,

    #[account(
        mut,
        seeds = [b"escrow", agent.key().as_ref(), instance_id.as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, PaymentEscrow>,

    #[account(
        mut,
        constraint = escrow_token_account.owner == escrow.key(),
    )]
    pub escrow_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = agent_token_account.owner == agent.key(),
    )]
    pub agent_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub agent: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct DepositPayment<'info> {
    #[account(
        init_if_needed,
        payer = agent,
        space = PAYMENT_ESCROW_SIZE,
        seeds = [b"escrow", agent.key().as_ref(), instance_id.as_ref()],
        bump,
    )]
    pub escrow: Box<Account<'info, PaymentEscrow>>,

    #[account(
        init_if_needed,
        payer = agent,
        associated_token::mint = usdc_mint,
        associated_token::authority = escrow,
    )]
    pub escrow_token_account: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = agent_token_account.owner == agent.key(),
        constraint = agent_token_account.mint == usdc_mint.key(),
    )]
    pub agent_token_account: Box<Account<'info, TokenAccount>>,

    pub usdc_mint: Box<Account<'info, Mint>>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        constraint = config.usdc_mint == usdc_mint.key() @ SupabaError::InvalidMint,
    )]
    pub config: Box<Account<'info, NetworkConfig>>,

    #[account(mut)]
    pub agent: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct DistributePayment<'info> {
    #[account(
        mut,
        seeds = [b"escrow", escrow.agent.as_ref(), instance_id.as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, PaymentEscrow>,

    #[account(
        mut,
        constraint = escrow_token_account.owner == escrow.key(),
    )]
    pub escrow_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"instance", instance.agent.as_ref(), instance_id.as_ref()],
        bump = instance.bump,
    )]
    pub instance: Account<'info, InstanceRecord>,

    /// Primary node operator's token account for receiving payment
    #[account(mut)]
    pub primary_operator_token_account: Account<'info, TokenAccount>,

    /// Anyone can crank
    pub cranker: Signer<'info>,

    pub token_program: Program<'info, Token>,
    // Remaining accounts: replica operator token accounts (up to 3)
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct CommitMerkleRoot<'info> {
    #[account(
        mut,
        seeds = [b"instance", instance.agent.as_ref(), instance_id.as_ref()],
        bump = instance.bump,
    )]
    pub instance: Account<'info, InstanceRecord>,

    #[account(
        constraint = primary_node.key() == instance.primary_node @ SupabaError::Unauthorized,
        constraint = primary_node.operator == operator.key() @ SupabaError::Unauthorized,
    )]
    pub primary_node: Account<'info, NodeRecord>,

    pub operator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct SlashNode<'info> {
    #[account(
        mut,
    )]
    pub node: Account<'info, NodeRecord>,

    #[account(
        seeds = [b"config"],
        bump = config.bump,
        constraint = config.authority == authority.key() @ SupabaError::Unauthorized,
    )]
    pub config: Account<'info, NetworkConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(instance_id: [u8; 16])]
pub struct MigrateInstance<'info> {
    #[account(
        mut,
        seeds = [b"instance", agent.key().as_ref(), instance_id.as_ref()],
        bump = instance.bump,
        constraint = instance.agent == agent.key() @ SupabaError::Unauthorized,
    )]
    pub instance: Account<'info, InstanceRecord>,

    #[account(
        mut,
        constraint = old_primary.key() == instance.primary_node @ SupabaError::InvalidPrimaryNode,
    )]
    pub old_primary: Account<'info, NodeRecord>,

    #[account(
        mut,
        constraint = new_primary.status == NodeStatus::Active @ SupabaError::NodeNotActive,
    )]
    pub new_primary: Account<'info, NodeRecord>,

    pub agent: Signer<'info>,
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[error_code]
pub enum SupabaError {
    #[msg("Endpoint exceeds maximum length of 256 characters")]
    EndpointTooLong,
    #[msg("Region exceeds maximum length of 32 characters")]
    RegionTooLong,
    #[msg("Capacity must be greater than zero")]
    InvalidCapacity,
    #[msg("Node is not in Active status")]
    NodeNotActive,
    #[msg("Node is not in Deregistering status")]
    NodeNotDeregistering,
    #[msg("Cooldown period has not elapsed")]
    CooldownNotElapsed,
    #[msg("Node still has active instances")]
    ActiveInstancesRemaining,
    #[msg("Node is at maximum capacity")]
    NodeAtCapacity,
    #[msg("Too many replica nodes (max 3)")]
    TooManyReplicas,
    #[msg("Encrypted DEK exceeds maximum length")]
    DekTooLong,
    #[msg("Unauthorized action")]
    Unauthorized,
    #[msg("Invalid status transition")]
    InvalidStatusTransition,
    #[msg("Instance is not in Active status")]
    InstanceNotActive,
    #[msg("Invalid USDC mint")]
    InvalidMint,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid slash percentage (must be 0-100)")]
    InvalidSlashPercentage,
    #[msg("Invalid cooldown value")]
    InvalidCooldown,
    #[msg("New capacity cannot be below active instance count")]
    CapacityBelowActive,
    #[msg("Replica account mismatch")]
    ReplicaAccountMismatch,
    #[msg("Invalid replica node account")]
    InvalidReplicaNode,
    #[msg("Replica node is not Active")]
    ReplicaNodeNotActive,
    #[msg("Invalid primary node")]
    InvalidPrimaryNode,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub min_stake: u64,
    pub default_rate: u64,
    pub usdc_mint: Pubkey,
}

#[event]
pub struct NodeRegistered {
    pub operator: Pubkey,
    pub endpoint: String,
    pub capacity: u8,
    pub stake: u64,
}

#[event]
pub struct NodeUpdated {
    pub operator: Pubkey,
}

#[event]
pub struct HeartbeatRecorded {
    pub operator: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct NodeDeregistering {
    pub operator: Pubkey,
    pub deregistering_at: i64,
}

#[event]
pub struct StakeClaimed {
    pub operator: Pubkey,
    pub amount: u64,
}

#[event]
pub struct InstanceAllocated {
    pub agent: Pubkey,
    pub instance_id: [u8; 16],
    pub primary_node: Pubkey,
}

#[event]
pub struct InstanceActivated {
    pub instance_id: [u8; 16],
}

#[event]
pub struct InstanceStatusUpdated {
    pub instance_id: [u8; 16],
}

#[event]
pub struct InstanceDestroyed {
    pub instance_id: [u8; 16],
    pub agent: Pubkey,
}

#[event]
pub struct PaymentDeposited {
    pub agent: Pubkey,
    pub instance_id: [u8; 16],
    pub amount: u64,
    pub total_deposited: u64,
}

#[event]
pub struct PaymentDistributed {
    pub instance_id: [u8; 16],
    pub amount: u64,
    pub remaining: u64,
}

#[event]
pub struct MerkleRootCommitted {
    pub instance_id: [u8; 16],
    pub root: [u8; 32],
}

#[event]
pub struct NodeSlashed {
    pub operator: Pubkey,
    pub slash_amount: u64,
    pub proof_type: SlashProofType,
}

#[event]
pub struct InstanceMigrated {
    pub instance_id: [u8; 16],
    pub old_primary: Pubkey,
    pub new_primary: Pubkey,
}
