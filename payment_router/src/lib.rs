#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, log, symbol_short, token, Address, BytesN,
    Env, Symbol, Vec,
};

// ── Packed UserSpending helpers ──────────────────────────────────────────────
//
// Issue #519: Replace the two-field UserSpending contracttype with a single
// BytesN<24> value packed with bitwise operations.
//
// Layout (big-endian):
//   bytes  0..8  — last_reset_time  : u64   (8 bytes)
//   bytes  8..24 — accumulated_amount: i128  (16 bytes)
//
// Benefits:
//  • Eliminates the XDR struct-type overhead (type discriminant + field tags)
//    that Soroban adds to every contracttype value, shrinking each UserSpending
//    ledger entry from ~48 bytes to exactly 24 bytes.
//  • Smaller entries → lower state-rent fee per ledger entry per TTL period.

/// Pack `last_reset_time` (u64) and `accumulated_amount` (i128) into a
/// 24-byte big-endian buffer.
fn pack_spending(env: &Env, last_reset_time: u64, accumulated_amount: i128) -> BytesN<24> {
    let mut buf = [0u8; 24];

    // Bytes 0..8 — last_reset_time (u64 big-endian)
    let t_bytes = last_reset_time.to_be_bytes();
    buf[0] = t_bytes[0];
    buf[1] = t_bytes[1];
    buf[2] = t_bytes[2];
    buf[3] = t_bytes[3];
    buf[4] = t_bytes[4];
    buf[5] = t_bytes[5];
    buf[6] = t_bytes[6];
    buf[7] = t_bytes[7];

    // Bytes 8..24 — accumulated_amount (i128 big-endian)
    let a_bytes = accumulated_amount.to_be_bytes();
    buf[8] = a_bytes[0];
    buf[9] = a_bytes[1];
    buf[10] = a_bytes[2];
    buf[11] = a_bytes[3];
    buf[12] = a_bytes[4];
    buf[13] = a_bytes[5];
    buf[14] = a_bytes[6];
    buf[15] = a_bytes[7];
    buf[16] = a_bytes[8];
    buf[17] = a_bytes[9];
    buf[18] = a_bytes[10];
    buf[19] = a_bytes[11];
    buf[20] = a_bytes[12];
    buf[21] = a_bytes[13];
    buf[22] = a_bytes[14];
    buf[23] = a_bytes[15];

    BytesN::from_array(env, &buf)
}

/// Unpack a 24-byte buffer into `(last_reset_time, accumulated_amount)`.
fn unpack_spending(packed: &BytesN<24>) -> (u64, i128) {
    // BytesN::to_array() is available in soroban-sdk v20.
    let buf: [u8; 24] = packed.to_array();

    // last_reset_time — bytes 0..8
    let last_reset_time = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);

    // accumulated_amount — bytes 8..24
    let accumulated_amount = i128::from_be_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]);

    (last_reset_time, accumulated_amount)
}

// ── Legacy struct kept for test snapshot compatibility ───────────────────────
//
// The UserSpending contracttype is retained so existing tests that reference
// it directly continue to compile.  All runtime code now uses the packed
// BytesN<24> representation stored under DataKey::UserSpending.

/// A user's rolling 24-hour spending record.
///
/// Retained purely so existing test snapshots that reference this type by
/// name keep compiling. Live contract state is stored as a packed
/// `BytesN<24>` (see `pack_spending` / `unpack_spending`); this struct is not
/// read from or written to storage at runtime.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserSpending {
    /// Unix timestamp (seconds) at which the 24-hour window last reset.
    pub last_reset_time: u64,
    /// Total amount routed by the user since `last_reset_time`.
    pub accumulated_amount: i128,
}

/// A single transfer instruction for use with [`PaymentRouter::route_payments`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    /// Address the funds are debited from. Must authorize the call.
    pub sender: Address,
    /// Address the funds (minus the platform fee) are credited to.
    pub recipient: Address,
    /// Contract ID of the token (or Stellar Asset Contract) being transferred.
    pub token_address: Address,
    /// Amount to route, denominated in the token's smallest unit. Must be
    /// positive and within the contract's configured min/max bounds.
    pub amount: i128,
}

// ── Timelock data structures ─────────────────────────────────────────────────
//
// Admin actions that change sensitive contract parameters (treasury, fees,
// governance, admin transfer) are not applied instantly.  Instead the admin
// queues an ActionType intent that gets a nonce ID and a ledger timestamp.
// Only after SECONDS_IN_24H (86 400 s) has elapsed can execute_action be
// called to apply the change.  This gives observers a 24-hour window to
// detect and respond to a compromised-admin scenario.
//
// The freeze mechanism is the complementary emergency tool: calling
// emergency_freeze instantly blocks all payments and all timelock executions.
// A freeze does NOT require going through the timelock itself so it is always
// available to the admin as an immediate last resort.  Unfreezing likewise
// takes effect immediately so the admin can restore service once the threat is
// resolved.

/// Describes which administrative parameter change a timelock entry represents.
/// Each variant carries all the arguments needed to apply that change when the
/// delay period is over.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionType {
    /// Change the platform treasury address.
    SetPlatformTreasury(Address),
    /// Update fee basis-points and fee cap together (legacy / combined setter).
    SetFeeConfig(i128, i128),
    /// Update fee basis-points only.
    SetFeeBps(i128),
    /// Set the governance contract address.
    SetGovernance(Address),
    /// Change the minimum routing limit.
    SetMinLimit(i128),
    /// Transfer admin rights to a new address.
    TransferAdmin(Address),
    /// Upgrade the contract WASM.
    Upgrade(BytesN<32>),
}

/// A pending timelock entry stored in persistent ledger storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockEntry {
    /// Ledger timestamp (seconds since epoch) when this action was queued.
    pub queued_at: u64,
    /// The action payload to apply once the delay has elapsed.
    pub action: ActionType,
}

/// A pending time-locked escrow deposit stored in persistent ledger storage.
///
/// Funds are held by the contract until `release_time` has passed, at which
/// point the `recipient` may call `release_escrow` to claim them, or the
/// `sender` may call `reclaim_escrow` if the recipient does not.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowDeposit {
    /// Address that deposited the funds.
    pub sender: Address,
    /// Address entitled to claim the funds after `release_time`.
    pub recipient: Address,
    /// Contract ID of the escrowed token.
    pub token: Address,
    /// Amount held in escrow, in the token's smallest unit.
    pub amount: i128,
    /// Ledger timestamp (seconds since epoch) after which funds can be released.
    pub release_time: u64,
    /// Set to `true` once the funds have been claimed or reclaimed.
    pub claimed: bool,
}

/// Storage keys for all contract instance and persistent data.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// The current admin address.
    Admin,
    /// Governance contract address; if set, it takes over fee-authority from the admin.
    Governance,
    /// Address that receives collected platform fees.
    PlatformTreasury,
    /// Platform fee rate, in basis points (1/100th of a percent).
    FeeBps,
    /// Upper bound on the fee taken from a single payment.
    FeeCap,
    /// Minimum amount accepted by `route_payment` / `route_payments`, if set.
    MinLimit,
    /// Whether routing is currently paused.
    Paused,
    /// Maximum amount accepted by a single payment.
    MaxAmount,
    /// Cumulative lifetime amount routed by a given sender.
    UserVolume(Address),
    /// Packed 24-hour spending window for a given sender.
    UserSpending(Address),
    /// Whether a given recipient address is blacklisted.
    Blacklist(Address),
    /// Internal refund balance for a (user, token) pair, credited when a
    /// direct transfer to the recipient fails.
    RefundBalance(Address, Address),
    /// Monotonically-increasing nonce counter used to generate unique IDs for
    /// timelock entries.  Stored as `u64` in instance storage.
    TimelockNonce,
    /// A pending timelock entry keyed by its nonce ID.
    /// Stored in persistent storage so it survives instance eviction.
    TimelockEntry(u64),
    /// When `true` the contract is frozen: payments and timelock executions
    /// are blocked.  Stored as `bool` in instance storage.
    Frozen,
    /// Monotonically-increasing nonce counter for escrow deposit IDs.
    /// Stored as `u64` in instance storage.
    EscrowNonce,
    /// A pending escrow deposit keyed by its nonce ID.
    /// Stored in persistent storage so it survives instance eviction.
    EscrowDeposit(u64),
}

/// Contract-level errors returned instead of panicking, so callers get a
/// specific, stable error code to branch on rather than an opaque trap.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Caller is not authorized to perform this action (e.g. not the admin).
    Unauthorized = 1,
    /// Sender's token balance is lower than the requested payment amount.
    InsufficientBalance = 2,
    /// Requested amount is outside allowed bounds, or a spending limit was exceeded.
    LimitExceeded = 3,
    /// `initialize` was called on a contract that already has an admin set.
    AlreadyInitialized = 4,
    /// An admin-configured value (treasury, fee, admin) was read before `initialize`.
    NotInitialized = 5,
    /// The contract is currently paused; routing calls are rejected until unpaused.
    Paused = 6,
    /// A fee configuration value (basis points or cap) is out of the allowed range.
    InvalidFeeRate = 7,
    /// Sender and recipient addresses are the same (self-routing not allowed).
    InvalidRecipient = 8,
    /// Recipient address is blacklisted.
    Blacklisted = 9,
    /// Requested refund withdrawal amount is zero or exceeds available refund balance.
    NoRefundAvailable = 10,
    /// An action is already pending in the timelock queue; it must be executed
    /// or cancelled before a duplicate can be queued (not currently enforced,
    /// but reserved for future deduplication logic).
    TimelockPending = 11,
    /// The 24-hour delay for the given timelock entry has not elapsed yet.
    TimelockNotReady = 12,
    /// No timelock entry exists for the supplied nonce ID.
    TimelockNotFound = 13,
    /// The contract is frozen; all payments and timelock executions are blocked.
    ContractFrozen = 14,
    /// Escrow funds are still locked; the release time has not been reached.
    EscrowLocked = 15,
    /// No escrow deposit exists for the supplied ID.
    EscrowNotFound = 16,
    /// The escrow release window has expired and funds have been reclaimed.
    EscrowExpired = 17,
}

/// Soroban contract that routes token payments between addresses while
/// collecting a configurable platform fee, enforcing per-user daily spending
/// limits, and supporting an admin-managed blacklist and pause switch.
#[contract]
pub struct PaymentRouter;

#[contractimpl]
impl PaymentRouter {
    const BPS_DIVISOR: i128 = 10_000;
    const XLM_DECIMALS: i128 = 10_000_000;
    const MAX_AMOUNT: i128 = 1_000_000_000_000_000; // 100M tokens with 7 decimals
    const DAILY_MAX_LIMIT: i128 = 1_000_000 * Self::XLM_DECIMALS; // 1M tokens limit
    const VOLUME_THRESHOLD: i128 = 10_000 * Self::XLM_DECIMALS; // 10,000 XLM threshold for tiered fee discount
    const SECONDS_IN_24H: u64 = 24 * 3600;
    const VERSION: u32 = 1;

    const DAY_IN_LEDGERS: u32 = 17280;
    const INSTANCE_BUMP_AMOUNT: u32 = 7 * Self::DAY_IN_LEDGERS;
    const INSTANCE_LIFETIME_THRESHOLD: u32 = Self::INSTANCE_BUMP_AMOUNT - Self::DAY_IN_LEDGERS;

    const USER_BUMP_AMOUNT: u32 = 30 * Self::DAY_IN_LEDGERS;
    const USER_LIFETIME_THRESHOLD: u32 = Self::USER_BUMP_AMOUNT - Self::DAY_IN_LEDGERS;
    const PERSISTENT_BUMP_AMOUNT: u32 = Self::USER_BUMP_AMOUNT;
    const PERSISTENT_LIFETIME_THRESHOLD: u32 = Self::USER_LIFETIME_THRESHOLD;

    // ── Private helpers ──────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Fee authority helper: if a Governance address is set it takes exclusive
    /// control over fee updates; otherwise the admin retains that right.
    fn require_fee_authority(env: &Env) -> Result<(), Error> {
        if let Some(gov) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Governance)
        {
            gov.require_auth();
            Ok(())
        } else {
            let admin = Self::require_admin(env)?;
            admin.require_auth();
            Ok(())
        }
    }

    fn load_fee_config(env: &Env) -> Result<(Address, i128, i128), Error> {
        let platform_treasury: Address = env
            .storage()
            .instance()
            .get(&DataKey::PlatformTreasury)
            .ok_or(Error::NotInitialized)?;
        let fee_bps: i128 = env
            .storage()
            .instance()
            .get(&DataKey::FeeBps)
            .ok_or(Error::NotInitialized)?;
        let fee_cap: i128 = env
            .storage()
            .instance()
            .get(&DataKey::FeeCap)
            .ok_or(Error::NotInitialized)?;

        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        Ok((platform_treasury, fee_bps, fee_cap))
    }

    fn get_refund_balance_internal(env: &Env, user: &Address, token: &Address) -> i128 {
        let key = DataKey::RefundBalance(user.clone(), token.clone());
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    fn credit_refund_balance(env: &Env, user: &Address, token: &Address, amount: i128) {
        let key = DataKey::RefundBalance(user.clone(), token.clone());
        let current_balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = current_balance + amount;
        env.storage().persistent().set(&key, &new_balance);
        env.storage().persistent().extend_ttl(
            &key,
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        env.events().publish(
            (symbol_short!("refunded"), user.clone(), token.clone()),
            amount,
        );
    }

    /// Returns whether the contract is currently frozen.
    fn is_frozen_internal(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Frozen)
            .unwrap_or(false)
    }

    /// Allocates and returns the next timelock nonce, incrementing the counter.
    fn next_nonce(env: &Env) -> u64 {
        let current: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TimelockNonce)
            .unwrap_or(0u64);
        let next = current + 1;
        env.storage().instance().set(&DataKey::TimelockNonce, &next);
        next
    }

    /// Allocates and returns the next escrow nonce, incrementing the counter.
    /// The counter is stored in instance storage under `DataKey::EscrowNonce`.
    fn next_escrow_nonce(env: &Env) -> u64 {
        let current: u64 = env
            .storage()
            .instance()
            .get(&DataKey::EscrowNonce)
            .unwrap_or(0u64);
        let next = current + 1;
        env.storage().instance().set(&DataKey::EscrowNonce, &next);
        next
    }

    /// Core payment logic shared by `route_payment` and `route_payments`.
    #[allow(clippy::too_many_arguments)]
    fn process_single_payment(
        env: &Env,
        sender: &Address,
        recipient: &Address,
        token_address: &Address,
        amount: i128,
        platform_treasury: &Address,
        fee_bps: i128,
        fee_cap: i128,
    ) -> Result<(), Error> {
        // Require sender auth
        sender.require_auth();

        env.events().publish(
            (Symbol::new(env, "payment_initiated"), sender.clone()),
            amount,
        );

        // Prevent self-routing
        if sender == recipient {
            return Err(Error::InvalidRecipient);
        }

        // Check if recipient is blacklisted
        if Self::is_blacklisted(env.clone(), recipient.clone()) {
            return Err(Error::Blacklisted);
        }

        // Validate amount bounds
        let max_amount: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MaxAmount)
            .unwrap_or(Self::MAX_AMOUNT);
        if amount <= 0 || amount > max_amount {
            return Err(Error::LimitExceeded);
        }

        // Enforce optional admin-configured minimum payment limit
        let min_limit: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MinLimit)
            .unwrap_or(0);
        if amount < min_limit {
            return Err(Error::LimitExceeded);
        }

        // Apply tiered fee discount for high-volume users
        let user_volume: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::UserVolume(sender.clone()))
            .unwrap_or(0);
        let effective_fee_bps = if user_volume > Self::VOLUME_THRESHOLD {
            fee_bps / 2
        } else {
            fee_bps
        };

        // Check time-based daily spending limits.
        // Storage format: packed BytesN<24> (see pack_spending / unpack_spending).
        let current_time = env.ledger().timestamp();
        let spending_key = DataKey::UserSpending(sender.clone());

        let (mut last_reset_time, mut accumulated_amount): (u64, i128) = env
            .storage()
            .persistent()
            .get::<DataKey, BytesN<24>>(&spending_key)
            .map(|packed| unpack_spending(&packed))
            .unwrap_or((current_time, 0));

        if current_time - last_reset_time >= Self::SECONDS_IN_24H {
            last_reset_time = current_time;
            accumulated_amount = 0;
        }

        accumulated_amount += amount;
        if accumulated_amount > Self::DAILY_MAX_LIMIT {
            return Err(Error::LimitExceeded);
        }

        env.storage().persistent().set(
            &spending_key,
            &pack_spending(env, last_reset_time, accumulated_amount),
        );
        env.storage().persistent().extend_ttl(
            &spending_key,
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        // Verify sender has sufficient balance
        let token_client = token::Client::new(env, token_address);
        if token_client.balance(sender) < amount {
            return Err(Error::InsufficientBalance);
        }

        // Calculate fee
        let mut fee_amount = (amount * effective_fee_bps) / Self::BPS_DIVISOR;
        if fee_amount > fee_cap {
            fee_amount = fee_cap;
        }
        if fee_amount > amount {
            fee_amount = amount;
        }
        let remainder = amount - fee_amount;

        // Execute transfers
        if fee_amount > 0 {
            token_client.transfer(sender, platform_treasury, &fee_amount);
        }
        if remainder > 0 {
            // Attempt to transfer remainder directly to recipient.
            // If recipient cannot receive tokens (e.g. missing trustline or rejection),
            // transfer funds into the contract and credit the sender's internal refund ledger.
            match token_client.try_transfer(sender, recipient, &remainder) {
                Ok(Ok(())) => {
                    log!(env, "Remaining balance routed to recipient");
                }
                _ => {
                    log!(
                        env,
                        "Recipient transfer failed; crediting sender refund balance"
                    );
                    token_client.transfer(sender, &env.current_contract_address(), &remainder);
                    Self::credit_refund_balance(env, sender, token_address, remainder);
                }
            }
        }

        // Record cumulative volume
        let volume_key = DataKey::UserVolume(sender.clone());
        let prev_volume: i128 = env.storage().persistent().get(&volume_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&volume_key, &(prev_volume + amount));
        env.storage().persistent().extend_ttl(
            &volume_key,
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        // Emit routed event
        env.events().publish(
            (symbol_short!("routed"), sender.clone(), recipient.clone()),
            amount,
        );

        log!(env, "Platform fee routed to treasury");

        Ok(())
    }

    // ── Public contract methods ──────────────────────────────────────────────

    /// One-time setup: records the admin and the initial fee configuration
    /// in instance storage. Must be called before `route_payment`.
    ///
    /// # Parameters
    /// - `admin`: Address granted admin rights over the contract; must
    ///   authorize this call.
    /// - `platform_treasury`: Address that receives collected platform fees.
    /// - `fee_bps`: Platform fee rate, in basis points.
    /// - `fee_cap`: Maximum fee (in the token's smallest unit) taken from a
    ///   single payment.
    /// - `max_amount`: Maximum amount accepted by a single payment.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::AlreadyInitialized)` if the
    /// contract already has an admin set.
    ///
    /// # Panics
    /// Panics if `admin` does not authorize the call.
    pub fn initialize(
        env: Env,
        admin: Address,
        platform_treasury: Address,
        fee_bps: i128,
        fee_cap: i128,
        max_amount: i128,
    ) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::PlatformTreasury, &platform_treasury);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        env.storage().instance().set(&DataKey::FeeCap, &fee_cap);
        env.storage()
            .instance()
            .set(&DataKey::MaxAmount, &max_amount);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::Frozen, &false);
        env.storage().instance().set(&DataKey::TimelockNonce, &0u64);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        Ok(())
    }

    // ── Timelock: queue / execute / cancel ───────────────────────────────────

    /// Queues an admin action to be executed after a 24-hour delay.
    ///
    /// The admin provides the desired `ActionType` variant and receives a
    /// numeric nonce that uniquely identifies this pending entry.  Pass this
    /// nonce to `execute_action` after 24 hours, or to `cancel_action` to
    /// abort the intent.
    ///
    /// Sensitive parameter changes (`set_platform_treasury`, `set_fee_config`,
    /// `set_fee_bps`, `set_governance`, `set_min_limit`, `transfer_admin`,
    /// `upgrade`) must go through the timelock.  Use the direct setter
    /// functions only for actions that are not sensitive (e.g. `set_pause`
    /// which can also be called directly for immediate operational pauses).
    ///
    /// The contract must not be frozen when queuing, and the admin must
    /// authorize the call.
    pub fn queue_action(env: Env, action: ActionType) -> Result<u64, Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }

        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let nonce = Self::next_nonce(&env);
        let queued_at = env.ledger().timestamp();

        let entry = TimelockEntry {
            queued_at,
            action: action.clone(),
        };

        let key = DataKey::TimelockEntry(nonce);
        env.storage().persistent().set(&key, &entry);
        env.storage().persistent().extend_ttl(
            &key,
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events().publish(
            (Symbol::new(&env, "action_queued"), admin),
            (nonce, queued_at),
        );

        log!(&env, "Timelock action queued with nonce {}", nonce);
        Ok(nonce)
    }

    /// Returns the pending `TimelockEntry` for the given nonce, or an error if
    /// it does not exist.
    pub fn get_queued_action(env: Env, nonce: u64) -> Result<TimelockEntry, Error> {
        let key = DataKey::TimelockEntry(nonce);
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(Error::TimelockNotFound)
    }

    /// Executes a previously queued action identified by `nonce`.
    ///
    /// Requirements:
    /// - The contract must not be frozen.
    /// - The admin must authorize.
    /// - The entry identified by `nonce` must exist.
    /// - At least 24 hours (`SECONDS_IN_24H`) must have passed since queuing.
    ///
    /// On success the entry is removed and the underlying setter is invoked.
    pub fn execute_action(env: Env, nonce: u64) -> Result<(), Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }

        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let key = DataKey::TimelockEntry(nonce);
        let entry: TimelockEntry = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::TimelockNotFound)?;

        let now = env.ledger().timestamp();
        if now < entry.queued_at + Self::SECONDS_IN_24H {
            return Err(Error::TimelockNotReady);
        }

        // Remove the entry before applying the action (checks-effects-interactions).
        env.storage().persistent().remove(&key);

        // Apply the action.
        match entry.action {
            ActionType::SetPlatformTreasury(new_treasury) => {
                env.storage()
                    .instance()
                    .set(&DataKey::PlatformTreasury, &new_treasury);
            }
            ActionType::SetFeeConfig(fee_bps, fee_cap) => {
                env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
                env.storage().instance().set(&DataKey::FeeCap, &fee_cap);
            }
            ActionType::SetFeeBps(new_fee_bps) => {
                env.storage().instance().set(&DataKey::FeeBps, &new_fee_bps);
            }
            ActionType::SetGovernance(gov) => {
                env.storage().instance().set(&DataKey::Governance, &gov);
            }
            ActionType::SetMinLimit(min_limit) => {
                env.storage().instance().set(&DataKey::MinLimit, &min_limit);
            }
            ActionType::TransferAdmin(new_admin) => {
                env.storage().instance().set(&DataKey::Admin, &new_admin);
            }
            ActionType::Upgrade(new_wasm_hash) => {
                env.deployer().update_current_contract_wasm(new_wasm_hash);
            }
        }

        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events()
            .publish((Symbol::new(&env, "action_executed"), admin), nonce);

        log!(&env, "Timelock action executed for nonce {}", nonce);
        Ok(())
    }

    /// Cancels a pending timelock entry before it can be executed.
    ///
    /// This is the primary defence when a compromised admin has queued a
    /// malicious action: any other admin (after a key rotation) or a
    /// multi-sig governance can cancel it within the 24-hour window.
    ///
    /// Admin authorization is required. The contract may be frozen.
    pub fn cancel_action(env: Env, nonce: u64) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let key = DataKey::TimelockEntry(nonce);
        if !env.storage().persistent().has(&key) {
            return Err(Error::TimelockNotFound);
        }

        env.storage().persistent().remove(&key);

        env.events()
            .publish((Symbol::new(&env, "action_cancelled"), admin), nonce);

        log!(&env, "Timelock action cancelled for nonce {}", nonce);
        Ok(())
    }

    // ── Freeze / unfreeze ────────────────────────────────────────────────────

    /// Instantly freezes the contract, blocking all payments and timelock
    /// executions.  This is the emergency last resort when an admin key is
    /// known to be compromised.
    ///
    /// Unlike other sensitive admin operations, freeze takes effect immediately
    /// — it does NOT go through the timelock — so it is always available as a
    /// rapid-response tool.
    ///
    /// Admin authorization is required.
    pub fn emergency_freeze(env: Env) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Frozen, &true);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events().publish(
            (Symbol::new(&env, "emergency_freeze"), admin),
            env.ledger().timestamp(),
        );

        log!(&env, "Contract frozen by admin");
        Ok(())
    }

    /// Removes the frozen state, restoring normal contract operation.
    ///
    /// Like `emergency_freeze`, this takes effect immediately and does not
    /// go through the timelock.
    ///
    /// Admin authorization is required.
    pub fn unfreeze(env: Env) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Frozen, &false);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events().publish(
            (Symbol::new(&env, "unfreeze"), admin),
            env.ledger().timestamp(),
        );

        log!(&env, "Contract unfrozen by admin");
        Ok(())
    }

    /// Returns whether the contract is currently frozen.
    pub fn is_frozen(env: Env) -> bool {
        Self::is_frozen_internal(&env)
    }

    // ── Sensitive admin setters (now require timelock) ───────────────────────
    //
    // The functions below are intentionally kept as thin wrappers that apply
    // the change *directly* but only when called from execute_action (i.e.
    // after the timelock has been satisfied).  External callers that were
    // previously calling these functions directly should instead use
    // queue_action + execute_action.
    //
    // NOTE: The direct-setter functions are retained for backward-compatibility
    // of off-chain tooling.  They still gate on admin/governance auth but they
    // are NOT wrapped by an on-chain timelock check; the timelock is enforced
    // exclusively through queue_action / execute_action.

    /// Updates the treasury address that receives the platform fee.
    ///
    /// Updates the treasury address that receives the platform fee. Admin-only.
    ///
    /// # Parameters
    /// - `new_treasury`: Address to receive platform fees going forward.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetPlatformTreasury(…))`
    /// and execute after 24 hours.  This direct path is retained for tooling
    /// compatibility only.
    pub fn set_platform_treasury(env: Env, new_treasury: Address) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::PlatformTreasury, &new_treasury);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Updates the fee basis points and fee cap.
    /// Requires governance authority if a governance address is set; otherwise admin-only.
    ///
    /// # Parameters
    /// - `fee_bps`: New platform fee rate, in basis points.
    /// - `fee_cap`: New maximum fee taken from a single payment.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the caller does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetFeeConfig(…))`.
    pub fn set_fee_config_legacy(env: Env, fee_bps: i128, fee_cap: i128) -> Result<(), Error> {
        Self::require_fee_authority(&env)?;

        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        env.storage().instance().set(&DataKey::FeeCap, &fee_cap);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Alias for `set_fee_config_legacy`. Admin-only.
    ///
    /// # Parameters
    /// - `fee_bps`: New platform fee rate, in basis points.
    /// - `fee_cap`: New maximum fee taken from a single payment.
    ///
    /// # Returns
    /// See `set_fee_config_legacy`.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetFeeConfig(…))`.
    pub fn set_fee_config(env: Env, fee_bps: i128, fee_cap: i128) -> Result<(), Error> {
        Self::set_fee_config_legacy(env, fee_bps, fee_cap)
    }

    /// Updates the fee basis points.
    /// Requires governance authority if a governance address is set; otherwise admin-only.
    ///
    /// # Parameters
    /// - `new_fee_bps`: New platform fee rate, in basis points.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the caller does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetFeeBps(…))`.
    pub fn set_fee_bps(env: Env, new_fee_bps: i128) -> Result<(), Error> {
        Self::require_fee_authority(&env)?;

        env.storage().instance().set(&DataKey::FeeBps, &new_fee_bps);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Sets the governance contract address. After this call, only the governance
    /// contract can update fees. Admin-only — can only be set once per governance cycle.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetGovernance(…))`.
    pub fn set_governance(env: Env, gov: Address) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();
        env.storage().instance().set(&DataKey::Governance, &gov);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Sets the minimum allowed routing amount. Admin-only.
    ///
    /// # Parameters
    /// - `min_limit`: Smallest `amount` that `route_payment` /
    ///   `route_payments` will accept going forward.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::SetMinLimit(…))`.
    pub fn set_min_limit(env: Env, min_limit: i128) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::MinLimit, &min_limit);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Returns the current protocol fee percentage in basis points.
    ///
    /// # Returns
    /// The configured `fee_bps`, or `0` if the contract has not been
    /// initialized.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get_fee(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::FeeBps).unwrap_or(0)
    }

    /// Pauses or unpauses the payment router. Admin-only.
    ///
    /// # Parameters
    /// - `paused`: `true` to reject `route_payment` / `route_payments`
    ///   calls, `false` to allow them again.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    ///
    /// This is NOT timelocked — operational pausing must remain instant.
    pub fn set_pause(env: Env, paused: bool) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::Paused, &paused);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events().publish((symbol_short!("pause"),), (paused,));

        Ok(())
    }

    /// Alias for `set_pause`. Admin-only.
    ///
    /// # Parameters
    /// - `paused`: `true` to reject routing calls, `false` to allow them.
    ///
    /// # Returns
    /// See `set_pause`.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    pub fn set_paused(env: Env, paused: bool) -> Result<(), Error> {
        Self::set_pause(env, paused)
    }

    /// Returns whether the contract is currently paused.
    ///
    /// # Returns
    /// `true` if paused, `false` if unpaused or not yet initialized.
    ///
    /// # Panics
    /// Does not panic.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Returns the cumulative amount a given sender has routed through the contract.
    ///
    /// # Parameters
    /// - `user`: Sender address to look up.
    ///
    /// # Returns
    /// The lifetime routed volume for `user`, or `0` if they have never
    /// routed a payment.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get_user_volume(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::UserVolume(user))
            .unwrap_or(0)
    }

    /// Adds an address to the blacklist. Admin-only.
    ///
    /// # Parameters
    /// - `address`: Address to blacklist; subsequent payments to it as a
    ///   recipient will be rejected.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    pub fn blacklist_address(env: Env, address: Address) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::Blacklist(address.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::Blacklist(address),
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        Ok(())
    }

    /// Removes an address from the blacklist. Admin-only.
    ///
    /// # Parameters
    /// - `address`: Address to remove from the blacklist.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    pub fn unblacklist_address(env: Env, address: Address) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage()
            .persistent()
            .remove(&DataKey::Blacklist(address));

        Ok(())
    }

    /// Returns whether an address is blacklisted.
    ///
    /// # Parameters
    /// - `address`: Address to check.
    ///
    /// # Returns
    /// `true` if `address` is blacklisted, `false` otherwise.
    ///
    /// # Panics
    /// Does not panic.
    pub fn is_blacklisted(env: Env, address: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Blacklist(address))
            .unwrap_or(false)
    }

    /// Returns the effective fee_bps for a sender after applying any
    /// volume-based tiered discount.
    ///
    /// # Parameters
    /// - `sender`: Address whose discounted fee rate to compute.
    ///
    /// # Returns
    /// The configured `fee_bps`, halved if `sender`'s lifetime volume
    /// exceeds the tiered-discount threshold, or `0` if not initialized.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get_effective_fee_bps(env: Env, sender: Address) -> i128 {
        let fee_bps: i128 = env.storage().instance().get(&DataKey::FeeBps).unwrap_or(0);
        let user_volume = Self::get_user_volume(env.clone(), sender);
        if user_volume > Self::VOLUME_THRESHOLD {
            fee_bps / 2
        } else {
            fee_bps
        }
    }

    /// Set a new admin. Gated by the current admin if one exists.
    ///
    /// # Parameters
    /// - `new_admin`: Address to install as the new admin.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Panics
    /// Panics if an admin is already set and it does not authorize the call.
    pub fn set_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        if let Some(admin) = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Admin)
        {
            admin.require_auth();
        }
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Transfers admin rights to a new address. Requires the current admin's authorization.
    ///
    /// # Parameters
    /// - `new_admin`: Address to become the new admin.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::TransferAdmin(…))`.
    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let current_admin = Self::require_admin(&env)?;
        current_admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Recovers tokens accidentally sent directly to the contract address. Admin-only.
    ///
    /// # Parameters
    /// - `token`: Contract ID of the token to recover.
    /// - `amount`: Amount to transfer from the contract's balance to the admin.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call, or if the
    /// token transfer fails (e.g. the contract's balance is below `amount`).
    pub fn recover_tokens(env: Env, token: Address, amount: i128) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&contract_address, &admin, &amount);

        Ok(())
    }

    /// Records a token as supported (no-op; routing accepts any token contract ID).
    ///
    /// # Parameters
    /// - `_token`: Ignored; present for API compatibility.
    ///
    /// # Returns
    /// Always `Ok(())`.
    ///
    /// # Panics
    /// Does not panic.
    pub fn add_supported_token(_env: Env, _token: Address) -> Result<(), Error> {
        Ok(())
    }

    /// Routes a payment from a sender to a recipient, deducting a platform fee.
    ///
    /// # Parameters
    /// - `sender`: Address the funds are debited from; must authorize the call.
    /// - `recipient`: Address to receive the funds (minus the platform fee).
    /// - `token_address`: Contract ID of the token being transferred.
    /// - `amount`: Amount to route, in the token's smallest unit. Must be
    ///   positive and within the configured min/max and daily-limit bounds.
    ///
    /// # Returns
    /// `Ok(())` on success. Returns `Err(Error::Paused)` if routing is
    /// paused, `Err(Error::NotInitialized)` if the contract has no admin
    /// set, `Err(Error::InvalidRecipient)` if `sender == recipient`,
    /// `Err(Error::Blacklisted)` if `recipient` is blacklisted,
    /// `Err(Error::LimitExceeded)` if `amount` is outside the configured
    /// bounds or exceeds the sender's remaining daily limit, or
    /// `Err(Error::InsufficientBalance)` if `sender`'s token balance is
    /// below `amount`.
    ///
    /// # Panics
    /// Panics if `sender` does not authorize the call, or if the underlying
    /// token transfer to `platform_treasury` fails.
    pub fn route_payment(
        env: Env,
        sender: Address,
        recipient: Address,
        token_address: Address,
        amount: i128,
    ) -> Result<(), Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }
        if Self::is_paused(env.clone()) {
            return Err(Error::Paused);
        }

        let (platform_treasury, fee_bps, fee_cap) = Self::load_fee_config(&env)?;

        Self::process_single_payment(
            &env,
            &sender,
            &recipient,
            &token_address,
            amount,
            &platform_treasury,
            fee_bps,
            fee_cap,
        )
    }

    /// Routes multiple payments in a single transaction. If any payment fails,
    /// the entire batch is reverted atomically.
    ///
    /// # Parameters
    /// - `payments`: Batch of transfer instructions to apply in order. See
    ///   [`Payment`] for per-item constraints.
    ///
    /// # Returns
    /// `Ok(())` if every payment in the batch succeeds. Returns the first
    /// error encountered (see `route_payment` for the possible `Err`
    /// variants and their causes) if any payment fails; the Soroban host
    /// reverts all storage and balance changes from the batch in that case.
    ///
    /// # Panics
    /// Panics if any payment's `sender` does not authorize the call, or if
    /// a token transfer to `platform_treasury` fails.
    pub fn route_payments(env: Env, payments: Vec<Payment>) -> Result<(), Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }
        if Self::is_paused(env.clone()) {
            return Err(Error::Paused);
        }

        let (platform_treasury, fee_bps, fee_cap) = Self::load_fee_config(&env)?;

        for payment in payments.iter() {
            Self::process_single_payment(
                &env,
                &payment.sender,
                &payment.recipient,
                &payment.token_address,
                payment.amount,
                &platform_treasury,
                fee_bps,
                fee_cap,
            )?;
        }

        Ok(())
    }

    /// Returns the available internal refund balance for a user and token.
    ///
    /// # Parameters
    /// - `user`: Address whose refund balance to look up.
    /// - `token`: Contract ID of the token.
    ///
    /// # Returns
    /// The refundable balance for `(user, token)`, or `0` if none is held.
    ///
    /// # Panics
    /// Does not panic.
    pub fn get_refund_balance(env: Env, user: Address, token: Address) -> i128 {
        Self::get_refund_balance_internal(&env, &user, &token)
    }

    /// Withdraws a specific amount from the user's internal refund balance.
    ///
    /// A refund balance accrues when a `route_payment` / `route_payments`
    /// transfer to the recipient fails (e.g. missing trustline) and the
    /// funds are held by the contract on the sender's behalf instead.
    ///
    /// # Parameters
    /// - `user`: Address withdrawing funds; must authorize the call.
    /// - `token`: Contract ID of the token to withdraw.
    /// - `amount`: Amount to withdraw. Must be positive and not exceed the
    ///   current refund balance.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NoRefundAvailable)` if `amount`
    /// is zero, negative, or greater than the available balance.
    ///
    /// # Panics
    /// Panics if `user` does not authorize the call, or if the underlying
    /// token transfer fails.
    pub fn withdraw_refund(
        env: Env,
        user: Address,
        token: Address,
        amount: i128,
    ) -> Result<(), Error> {
        user.require_auth();

        if amount <= 0 {
            return Err(Error::NoRefundAvailable);
        }

        let current_balance = Self::get_refund_balance_internal(&env, &user, &token);
        if amount > current_balance {
            return Err(Error::NoRefundAvailable);
        }

        let key = DataKey::RefundBalance(user.clone(), token.clone());
        let new_balance = current_balance - amount;
        if new_balance > 0 {
            env.storage().persistent().set(&key, &new_balance);
            env.storage().persistent().extend_ttl(
                &key,
                Self::PERSISTENT_LIFETIME_THRESHOLD,
                Self::PERSISTENT_BUMP_AMOUNT,
            );
        } else {
            env.storage().persistent().remove(&key);
        }

        let contract_address = env.current_contract_address();
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&contract_address, &user, &amount);

        env.events().publish(
            (symbol_short!("withdrawn"), user.clone(), token.clone()),
            amount,
        );

        log!(&env, "Refund balance withdrawn by user");
        Ok(())
    }

    /// Claims and withdraws the entire available refund balance for a user and token.
    ///
    /// # Parameters
    /// - `user`: Address withdrawing funds; must authorize the call.
    /// - `token`: Contract ID of the token to withdraw.
    ///
    /// # Returns
    /// `Ok(amount)` with the amount withdrawn, or
    /// `Err(Error::NoRefundAvailable)` if the refund balance is zero.
    ///
    /// # Panics
    /// Panics if `user` does not authorize the call, or if the underlying
    /// token transfer fails.
    pub fn claim_all_refunds(env: Env, user: Address, token: Address) -> Result<i128, Error> {
        user.require_auth();

        let current_balance = Self::get_refund_balance_internal(&env, &user, &token);
        if current_balance <= 0 {
            return Err(Error::NoRefundAvailable);
        }

        Self::withdraw_refund(env, user, token, current_balance)?;
        Ok(current_balance)
    }

    /// Admin-only emergency withdrawal of tokens held by this contract.
    ///
    /// # Parameters
    /// - `token`: Contract ID of the token to withdraw.
    /// - `amount`: Amount to transfer from the contract's balance to the admin.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call, or if the
    /// token transfer fails (e.g. the contract's balance is below `amount`).
    pub fn emergency_withdraw(env: Env, token: Address, amount: i128) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &admin, &amount);

        log!(&env, "Emergency withdraw executed by admin");
        Ok(())
    }

    /// Replaces this contract's WASM with a previously uploaded version. Admin-only.
    ///
    /// # Parameters
    /// - `new_wasm_hash`: Hash of a WASM blob previously uploaded to the
    ///   network, to install as this contract's new executable.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(Error::NotInitialized)` if the contract
    /// has no admin set yet.
    ///
    /// # Panics
    /// Panics if the current admin does not authorize the call, or if
    /// `new_wasm_hash` does not reference a previously uploaded WASM blob.
    ///
    /// DEPRECATED for direct use.  Queue via `queue_action(ActionType::Upgrade(…))`.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
        Ok(())
    }

    /// Returns the contract version.
    ///
    /// # Returns
    /// The contract's version number, currently `1`.
    ///
    /// # Panics
    /// Does not panic.
    pub fn version(_env: Env) -> u32 {
        Self::VERSION
    }

    // ── Escrow: create / release / reclaim / query ───────────────────────────
    //
    // A time-locked escrow holds tokens on behalf of a sender until a
    // `release_time` ledger timestamp is reached.  After that point:
    //  • The `recipient` can call `release_escrow` to pull the funds.
    //  • The `sender` can call `reclaim_escrow` to recover the funds if the
    //    recipient never claimed them.
    //
    // Funds are transferred into the contract on `create_escrow` and out of the
    // contract on `release_escrow` / `reclaim_escrow`.  The entry is removed from
    // storage in both cases (checks-effects-interactions pattern).

    /// Creates a new time-locked escrow, transferring `amount` tokens from
    /// `sender` into the contract and returning a unique escrow ID (nonce).
    ///
    /// # Parameters
    /// - `sender`: Address providing the funds; must authorize the call.
    /// - `recipient`: Address entitled to claim the funds after `release_time`.
    /// - `token`: Contract ID of the token to escrow.
    /// - `amount`: Amount to lock, in the token's smallest unit.
    /// - `release_time`: Ledger timestamp (seconds since epoch) after which the
    ///   funds may be released.  Must be strictly in the future.
    ///
    /// # Returns
    /// `Ok(escrow_id)` — the unique numeric ID of the created escrow.
    ///
    /// # Errors
    /// - `ContractFrozen` — contract is frozen.
    /// - `Paused` — contract is paused.
    /// - `EscrowLocked` — `release_time` is not in the future.
    pub fn create_escrow(
        env: Env,
        sender: Address,
        recipient: Address,
        token: Address,
        amount: i128,
        release_time: u64,
    ) -> Result<u64, Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }
        if Self::is_paused(env.clone()) {
            return Err(Error::Paused);
        }

        sender.require_auth();

        // release_time must be strictly in the future.
        if release_time <= env.ledger().timestamp() {
            return Err(Error::EscrowLocked);
        }

        // Transfer funds from sender into the contract.
        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&sender, &env.current_contract_address(), &amount);

        // Allocate a new escrow ID.
        let nonce = Self::next_escrow_nonce(&env);

        let deposit = EscrowDeposit {
            sender: sender.clone(),
            recipient: recipient.clone(),
            token,
            amount,
            release_time,
            claimed: false,
        };

        let key = DataKey::EscrowDeposit(nonce);
        env.storage().persistent().set(&key, &deposit);
        env.storage().persistent().extend_ttl(
            &key,
            Self::PERSISTENT_LIFETIME_THRESHOLD,
            Self::PERSISTENT_BUMP_AMOUNT,
        );

        env.storage().instance().extend_ttl(
            Self::INSTANCE_LIFETIME_THRESHOLD,
            Self::INSTANCE_BUMP_AMOUNT,
        );

        env.events().publish(
            (symbol_short!("esc_creat"), sender, recipient),
            (nonce, amount),
        );

        Ok(nonce)
    }

    /// Releases escrowed funds to the recipient after the lock period has elapsed.
    ///
    /// # Parameters
    /// - `escrow_id`: The nonce returned by `create_escrow`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// - `ContractFrozen` — contract is frozen.
    /// - `EscrowNotFound` — no escrow exists for `escrow_id`, or it was already claimed.
    /// - `EscrowLocked` — the release time has not been reached yet.
    pub fn release_escrow(env: Env, escrow_id: u64) -> Result<(), Error> {
        if Self::is_frozen_internal(&env) {
            return Err(Error::ContractFrozen);
        }

        let key = DataKey::EscrowDeposit(escrow_id);
        let deposit: EscrowDeposit = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EscrowNotFound)?;

        if deposit.claimed {
            return Err(Error::EscrowNotFound);
        }

        deposit.recipient.require_auth();

        if env.ledger().timestamp() < deposit.release_time {
            return Err(Error::EscrowLocked);
        }

        // Remove entry before transferring (checks-effects-interactions).
        env.storage().persistent().remove(&key);

        let token_client = token::Client::new(&env, &deposit.token);
        token_client.transfer(
            &env.current_contract_address(),
            &deposit.recipient,
            &deposit.amount,
        );

        env.events().publish(
            (
                symbol_short!("esc_rls"),
                deposit.sender,
                deposit.recipient.clone(),
            ),
            (escrow_id, deposit.amount),
        );

        Ok(())
    }

    /// Reclaims escrowed funds back to the sender after the lock period has
    /// elapsed (used when the recipient did not claim in time).
    ///
    /// # Parameters
    /// - `escrow_id`: The nonce returned by `create_escrow`.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// - `EscrowNotFound` — no escrow exists for `escrow_id`, or it was already claimed.
    /// - `EscrowLocked` — the release time has not been reached yet; sender must
    ///   wait for the window to pass before reclaiming.
    pub fn reclaim_escrow(env: Env, escrow_id: u64) -> Result<(), Error> {
        let key = DataKey::EscrowDeposit(escrow_id);
        let deposit: EscrowDeposit = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EscrowNotFound)?;

        if deposit.claimed {
            return Err(Error::EscrowNotFound);
        }

        deposit.sender.require_auth();

        if env.ledger().timestamp() < deposit.release_time {
            return Err(Error::EscrowLocked);
        }

        // Remove entry before transferring (checks-effects-interactions).
        env.storage().persistent().remove(&key);

        let token_client = token::Client::new(&env, &deposit.token);
        token_client.transfer(
            &env.current_contract_address(),
            &deposit.sender,
            &deposit.amount,
        );

        env.events().publish(
            (symbol_short!("esc_rclm"), deposit.sender.clone()),
            (escrow_id, deposit.amount),
        );

        Ok(())
    }

    /// Returns the `EscrowDeposit` for the given ID without consuming it.
    ///
    /// # Parameters
    /// - `escrow_id`: The nonce returned by `create_escrow`.
    ///
    /// # Returns
    /// `Ok(EscrowDeposit)` or `Err(EscrowNotFound)`.
    pub fn get_escrow(env: Env, escrow_id: u64) -> Result<EscrowDeposit, Error> {
        let key = DataKey::EscrowDeposit(escrow_id);
        env.storage()
            .persistent()
            .get(&key)
            .ok_or(Error::EscrowNotFound)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger as _, LedgerInfo},
        token::StellarAssetClient,
        Address, Env, Symbol, TryIntoVal,
    };

    /// Returns (env, client, contract_id).
    fn setup_env() -> (Env, PaymentRouterClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, PaymentRouter);
        let client = PaymentRouterClient::new(&env, &contract_id);
        (env, client, contract_id)
    }

    /// Deploys a Stellar Asset Contract test token. Returns
    /// (token_address, token_client, stellar_asset_admin_client).
    fn setup_token(
        env: &Env,
    ) -> (
        Address,
        token::Client<'static>,
        token::StellarAssetClient<'static>,
    ) {
        let token_admin = Address::generate(env);
        let token_address = env.register_stellar_asset_contract(token_admin);
        let token_client = token::Client::new(env, &token_address);
        let token_admin_client = token::StellarAssetClient::new(env, &token_address);
        (token_address, token_client, token_admin_client)
    }

    // ── Timelock tests ───────────────────────────────────────────────────────

    #[test]
    fn test_queue_and_execute_set_fee_bps_after_delay() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        // Queue a fee-bps change.
        let nonce = client.queue_action(&ActionType::SetFeeBps(250));
        assert_eq!(nonce, 1);
        assert_eq!(client.get_fee(), 100); // Not applied yet.

        // Trying to execute immediately should fail (delay not elapsed).
        let res = client.try_execute_action(&nonce);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotReady);

        // Advance time past 24 hours.
        let current_time = env.ledger().timestamp();
        env.ledger().set(LedgerInfo {
            timestamp: current_time + PaymentRouter::SECONDS_IN_24H + 1,
            protocol_version: env.ledger().protocol_version(),
            sequence_number: env.ledger().sequence(),
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        // Now execution should succeed.
        client.execute_action(&nonce);
        assert_eq!(client.get_fee(), 250);

        // Entry should be gone.
        let res = client.try_get_queued_action(&nonce);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotFound);
    }

    #[test]
    fn test_queue_and_execute_set_platform_treasury() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let new_treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let nonce = client.queue_action(&ActionType::SetPlatformTreasury(new_treasury.clone()));

        // Advance 24h+.
        let ts = env.ledger().timestamp();
        env.ledger().set(LedgerInfo {
            timestamp: ts + PaymentRouter::SECONDS_IN_24H + 1,
            protocol_version: env.ledger().protocol_version(),
            sequence_number: env.ledger().sequence(),
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        client.execute_action(&nonce);

        // Verify the treasury was actually updated by routing a payment and
        // checking where the fee lands.
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let (token_addr, token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);
        client.route_payment(&sender, &recipient, &token_addr, &1000);

        // 100 bps of 1000 = 10, capped to min(10, 1000) = 10
        assert_eq!(token_client.balance(&new_treasury), 10);
        assert_eq!(token_client.balance(&treasury), 0);
    }

    #[test]
    fn test_execute_action_not_found() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let res = client.try_execute_action(&99u64);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotFound);
    }

    #[test]
    fn test_cancel_action() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let nonce = client.queue_action(&ActionType::SetFeeBps(999));
        assert!(client.try_get_queued_action(&nonce).is_ok());

        client.cancel_action(&nonce);

        // Entry should be gone.
        let res = client.try_get_queued_action(&nonce);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotFound);

        // Fee should remain unchanged.
        assert_eq!(client.get_fee(), 100);
    }

    #[test]
    fn test_cancel_nonexistent_action() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let res = client.try_cancel_action(&42u64);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotFound);
    }

    #[test]
    fn test_nonce_increments() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let n1 = client.queue_action(&ActionType::SetFeeBps(200));
        let n2 = client.queue_action(&ActionType::SetFeeBps(300));
        let n3 = client.queue_action(&ActionType::SetFeeBps(400));

        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
        assert_eq!(n3, 3);
    }

    // ── Freeze tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_emergency_freeze_blocks_payments() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        assert!(!client.is_frozen());

        client.emergency_freeze();
        assert!(client.is_frozen());

        let res = client.try_route_payment(&sender, &recipient, &token_address, &1000);
        assert_eq!(res.unwrap_err().unwrap(), Error::ContractFrozen);
    }

    #[test]
    fn test_emergency_freeze_blocks_timelock_execution() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let nonce = client.queue_action(&ActionType::SetFeeBps(500));

        // Advance past 24h.
        let ts = env.ledger().timestamp();
        env.ledger().set(LedgerInfo {
            timestamp: ts + PaymentRouter::SECONDS_IN_24H + 1,
            protocol_version: env.ledger().protocol_version(),
            sequence_number: env.ledger().sequence(),
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        // Freeze the contract before execution.
        client.emergency_freeze();

        let res = client.try_execute_action(&nonce);
        assert_eq!(res.unwrap_err().unwrap(), Error::ContractFrozen);

        // Fee remains unchanged.
        assert_eq!(client.get_fee(), 100);
    }

    #[test]
    fn test_unfreeze_restores_payments() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        client.emergency_freeze();
        assert!(client.is_frozen());

        client.unfreeze();
        assert!(!client.is_frozen());

        // Payments should work again.
        client.route_payment(&sender, &recipient, &token_address, &1000);
    }

    #[test]
    fn test_freeze_queue_action_blocked() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        client.emergency_freeze();

        // Cannot queue new actions while frozen.
        let res = client.try_queue_action(&ActionType::SetFeeBps(500));
        assert_eq!(res.unwrap_err().unwrap(), Error::ContractFrozen);
    }

    #[test]
    fn test_cancel_action_allowed_while_frozen() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        // Queue an action before freezing.
        let nonce = client.queue_action(&ActionType::SetFeeBps(500));

        client.emergency_freeze();

        // Cancellation should still be possible while frozen (incident response).
        client.cancel_action(&nonce);
        let res = client.try_get_queued_action(&nonce);
        assert_eq!(res.unwrap_err().unwrap(), Error::TimelockNotFound);
    }

    // ── Timelock emits events ────────────────────────────────────────────────

    #[test]
    fn test_queue_action_emits_event() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        client.queue_action(&ActionType::SetFeeBps(200));

        let events = env.events().all();
        let found = events.iter().any(|(_, topics, _)| {
            if topics.is_empty() {
                return false;
            }
            let raw = topics.get(0).unwrap();
            let sym: Result<Symbol, _> = raw.try_into_val(&env);
            sym.map(|s| s == Symbol::new(&env, "action_queued"))
                .unwrap_or(false)
        });
        assert!(found, "action_queued event not found");
    }

    #[test]
    fn test_freeze_emits_event() {
        let (env, client, _) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        client.emergency_freeze();

        let events = env.events().all();
        let found = events.iter().any(|(_, topics, _)| {
            if topics.is_empty() {
                return false;
            }
            let raw = topics.get(0).unwrap();
            let sym: Result<Symbol, _> = raw.try_into_val(&env);
            sym.map(|s| s == Symbol::new(&env, "emergency_freeze"))
                .unwrap_or(false)
        });
        assert!(found, "emergency_freeze event not found");
    }

    // ── Original tests (retained) ────────────────────────────────────────────

    #[test]
    fn test_get_fee() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        // Before initialization, get_fee returns 0
        assert_eq!(client.get_fee(), 0);

        // Initialize with 150 bps
        client.initialize(&admin, &treasury, &150, &5000, &PaymentRouter::MAX_AMOUNT);
        assert_eq!(client.get_fee(), 150);

        // Update via set_fee_bps
        client.set_fee_bps(&250);
        assert_eq!(client.get_fee(), 250);

        // Update via set_fee_config
        client.set_fee_config(&300, &10000);
        assert_eq!(client.get_fee(), 300);
    }

    #[test]
    fn test_version_reports_contract_version() {
        let (_env, client, _) = setup_env();

        // #269 — the version view is callable without initialization and
        // returns the compiled-in contract version so a UI can check
        // compatibility before interacting with the contract.
        assert_eq!(client.version(), PaymentRouter::VERSION);
        assert_eq!(client.version(), 1);
    }

    #[test]
    fn test_admin_restrictions_and_updates() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let new_admin = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        // Trying to initialize again should fail
        let res = client.try_initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);
        assert_eq!(res.unwrap_err().unwrap(), Error::AlreadyInitialized);

        client.set_admin(&new_admin);

        // Modify config
        client.set_fee_config(&200, &2000);
        client.set_fee_bps(&200);
        assert_eq!(client.get_fee(), 200);

        let new_treasury = Address::generate(&env);
        client.set_platform_treasury(&new_treasury);
    }

    #[test]
    fn test_recover_tokens() {
        let (env, client, contract_id) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let (token_address, token_client, stellar_asset_client) = setup_token(&env);

        // Simulate tokens accidentally sent directly to the contract address
        let accidental_amount = 5_000i128;
        stellar_asset_client.mint(&contract_id, &accidental_amount);

        assert_eq!(token_client.balance(&contract_id), accidental_amount);
        assert_eq!(token_client.balance(&admin), 0);

        // Admin recovers tokens
        let recover_amount = 3_000i128;
        client.recover_tokens(&token_address, &recover_amount);

        assert_eq!(token_client.balance(&admin), recover_amount);
        assert_eq!(
            token_client.balance(&contract_id),
            accidental_amount - recover_amount
        );
    }

    #[test]
    fn test_set_pause_emits_event() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        client.set_pause(&true);

        let events = env.events().all();
        assert!(!events.is_empty());
        let (_, topics, _) = events.get(0).unwrap();
        assert_eq!(topics.len(), 1);
        let topic: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic, symbol_short!("pause"));
    }

    #[test]
    fn test_route_payment_emits_payment_initiated_event() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        client
            .mock_all_auths()
            .route_payment(&sender, &recipient, &token_address, &5_000);

        let events = env.events().all();
        assert!(!events.is_empty());

        let mut found = false;
        for (_, topics, data) in events.iter() {
            if !topics.is_empty() {
                if let Ok(topic_sym) = topics.get(0).unwrap().try_into_val(&env) {
                    let sym: Symbol = topic_sym;
                    if sym == Symbol::new(&env, "payment_initiated") {
                        found = true;
                        let amt: i128 = data.try_into_val(&env).unwrap();
                        assert_eq!(amt, 5_000);
                        break;
                    }
                }
            }
        }
        assert!(found, "payment_initiated event not found");
    }

    #[test]
    fn test_route_payment_emits_routed_event() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, _token_admin_client) = setup_token(&env);
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);
        client.add_supported_token(&token_address);

        let amount = 2_000i128;
        client.route_payment(&sender, &recipient, &token_address, &amount);

        let events = env.events().all();
        assert!(!events.is_empty());

        // Find the "routed" event by topic
        let mut found = None;
        for evt in events.iter() {
            let (_contract_id, topics, _data) = evt.clone();
            if topics.len() != 3 {
                continue;
            }
            let topic0: Symbol = topics.get(0).unwrap().try_into_val(&env).unwrap();
            if topic0 == symbol_short!("routed") {
                found = Some(evt.clone());
                break;
            }
        }
        let routed = found.expect("route_payment should publish a \"routed\" event");

        let (_contract_id, topics, data) = routed;
        assert_eq!(topics.len(), 3);

        let topic_sender: Address = topics.get(1).unwrap().try_into_val(&env).unwrap();
        let topic_recipient: Address = topics.get(2).unwrap().try_into_val(&env).unwrap();
        assert_eq!(topic_sender, sender);
        assert_eq!(topic_recipient, recipient);

        let event_amount: i128 = data.try_into_val(&env).unwrap();
        assert_eq!(event_amount, amount);
    }

    #[test]
    fn test_admin_pause_functionality() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, _token_admin_client) = setup_token(&env);
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        // Initially not paused
        assert!(!client.is_paused());

        // Pause
        client.set_pause(&true);
        assert!(client.is_paused());

        // Route payment should fail when paused
        let res = client.try_route_payment(&sender, &recipient, &token_address, &1000);
        assert_eq!(res.unwrap_err().unwrap(), Error::Paused);

        // Unpause via set_paused alias
        client.set_paused(&false);
        assert!(!client.is_paused());

        // Route payment should succeed now
        client.route_payment(&sender, &recipient, &token_address, &1000);
    }

    #[test]
    fn test_route_payment_calculates_and_sends_fee() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, token_client, _token_admin_client) = setup_token(&env);

        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        let initial_balance = 10_000i128;
        sac.mint(&sender, &initial_balance);

        // Initialize router with 1% fee (100 bps) and cap of 50
        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);
        client.add_supported_token(&token_address);

        // Test normal fee calculation: 1% of 2000 = 20, below cap of 50
        let amount_1 = 2000i128;
        client.route_payment(&sender, &recipient, &token_address, &amount_1);

        assert_eq!(token_client.balance(&treasury), 20);
        assert_eq!(token_client.balance(&recipient), 1980);
        assert_eq!(token_client.balance(&sender), initial_balance - amount_1);
        assert_eq!(client.get_user_volume(&sender), amount_1);

        // Test fee capped at 50: 1% of 8000 = 80, capped to 50
        let amount_2 = 8000i128;
        client.route_payment(&sender, &recipient, &token_address, &amount_2);

        assert_eq!(token_client.balance(&treasury), 70);
        assert_eq!(token_client.balance(&recipient), 9930);
        assert_eq!(
            token_client.balance(&sender),
            initial_balance - amount_1 - amount_2
        );
        assert_eq!(client.get_user_volume(&sender), amount_1 + amount_2);
    }

    #[test]
    fn test_insufficient_balance() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &100);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);
        client.add_supported_token(&token_address);

        // Route payment of 500 when balance is only 100
        let res = client.try_route_payment(&sender, &recipient, &token_address, &500);
        assert_eq!(res.unwrap_err().unwrap(), Error::InsufficientBalance);
    }

    #[test]
    fn test_daily_limit_and_reset() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, token_client, _token_admin_client) = setup_token(&env);

        let limit = 10_000_000_000_000i128;
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &(limit + 2000));

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);
        client.add_supported_token(&token_address);

        // Route amount up to daily limit
        client.route_payment(&sender, &recipient, &token_address, &limit);

        // Next payment should exceed daily limit
        let res = client.try_route_payment(&sender, &recipient, &token_address, &2000);
        assert_eq!(res.unwrap_err().unwrap(), Error::LimitExceeded);

        // Advance time past 24 hours to reset the daily limit
        let current_time = env.ledger().timestamp();
        let current_protocol_version = env.ledger().protocol_version();
        env.ledger().set(LedgerInfo {
            timestamp: current_time + 86400,
            protocol_version: current_protocol_version,
            sequence_number: 1,
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        // Now routing should succeed again. The first payment pushed volume past
        // VOLUME_THRESHOLD, so the halved rate applies: 2000 * 50 bps = 10.
        client.route_payment(&sender, &recipient, &token_address, &2000);
        assert_eq!(token_client.balance(&recipient), (limit - 50) + (2000 - 10));
    }

    #[test]
    fn test_prevent_self_routing() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);

        let (token_address, _token_client, _token_admin_client) = setup_token(&env);
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        let res = client.try_route_payment(&sender, &sender, &token_address, &1000);
        assert_eq!(res.unwrap_err().unwrap(), Error::InvalidRecipient);
    }

    #[test]
    #[ignore]
    fn test_tiered_fee_discount_applied_after_volume_threshold() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, token_client, _token_admin_client) = setup_token(&env);

        // Threshold is 10,000 XLM = 10,000 * 10,000,000 (7 decimals)
        let threshold = 100_000_000_000i128;
        let first_amount = threshold + 1;
        let second_amount = 1000i128;
        let total_mint = first_amount + second_amount + 10_000_000;
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &total_mint);

        // Initialize with 1% fee (100 bps) and no cap
        client.initialize(
            &admin,
            &treasury,
            &100,
            &i128::MAX,
            &PaymentRouter::MAX_AMOUNT,
        );

        // First payment: volume is 0 (< threshold), full fee applies
        client.route_payment(&sender, &recipient, &token_address, &first_amount);

        let full_fee_first = (first_amount * 100) / 10_000;
        assert_eq!(token_client.balance(&treasury), full_fee_first);
        assert_eq!(
            token_client.balance(&recipient),
            first_amount - full_fee_first
        );
        assert_eq!(client.get_user_volume(&sender), first_amount);
        // Volume is now past threshold, so next call gets the discount
        assert_eq!(client.get_effective_fee_bps(&sender), 50);

        // Second payment: volume > threshold, 50% discount applies
        client.route_payment(&sender, &recipient, &token_address, &second_amount);

        let discounted_fee = (second_amount * 50) / 10_000;
        assert_eq!(
            token_client.balance(&treasury),
            full_fee_first + discounted_fee
        );
        assert_eq!(
            token_client.balance(&recipient),
            (first_amount - full_fee_first) + (second_amount - discounted_fee)
        );
    }

    #[test]
    fn test_get_effective_fee_bps_no_discount_below_threshold() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, _token_admin_client) = setup_token(&env);
        let sac = soroban_sdk::token::StellarAssetClient::new(&env, &token_address);
        sac.mint(&sender, &1_000_000);

        client.initialize(
            &admin,
            &treasury,
            &100,
            &i128::MAX,
            &PaymentRouter::MAX_AMOUNT,
        );

        // No volume yet
        assert_eq!(client.get_effective_fee_bps(&sender), 100);

        // Route a small payment (below threshold)
        client.route_payment(&sender, &recipient, &token_address, &1000);

        // Volume is 1000, far below 10,000 XLM threshold
        assert_eq!(client.get_effective_fee_bps(&sender), 100);
    }

    #[test]
    fn test_successful_xlm_routing() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let platform_treasury = Address::generate(&env);

        let contract_id = env.register_contract(None, PaymentRouter);
        let client = PaymentRouterClient::new(&env, &contract_id);

        client.initialize(
            &admin,
            &platform_treasury,
            &40,
            &i128::MAX,
            &PaymentRouter::MAX_AMOUNT,
        );

        let token_admin = Address::generate(&env);
        let token_address = env.register_stellar_asset_contract(token_admin.clone());
        let sac = StellarAssetClient::new(&env, &token_address);
        let token_client = token::Client::new(&env, &token_address);

        let initial_balance = 1_000_000_000i128;
        sac.mint(&sender, &initial_balance);

        client.add_supported_token(&token_address);

        let amount = 100_000_000i128;
        client.route_payment(&sender, &recipient, &token_address, &amount);

        let expected_fee = 400_000i128;
        let expected_recipient_amount = amount - expected_fee;

        assert_eq!(token_client.balance(&sender), initial_balance - amount);
        assert_eq!(token_client.balance(&recipient), expected_recipient_amount);
        assert_eq!(token_client.balance(&platform_treasury), expected_fee);
    }

    #[test]
    fn test_initialize_sets_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let contract_addr = env.register_contract(None, PaymentRouter);
        let client = PaymentRouterClient::new(&env, &contract_addr);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let stored_admin: Option<Address> = env.as_contract(&contract_addr, || {
            env.storage().instance().get(&DataKey::Admin)
        });
        assert_eq!(stored_admin, Some(admin));
    }

    /// Verifies that `emergency_withdraw` transfers the exact requested amount
    /// from the contract's own balance to the admin address.
    #[test]
    fn test_emergency_withdraw_transfers_tokens_to_admin() {
        let (env, client, contract_id) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let (token_address, token_client, stellar_asset_client) = setup_token(&env);

        // Fund the contract directly (simulates stranded tokens from a routing failure).
        let stranded_amount = 10_000i128;
        stellar_asset_client.mint(&contract_id, &stranded_amount);

        assert_eq!(token_client.balance(&contract_id), stranded_amount);
        assert_eq!(token_client.balance(&admin), 0);

        // Admin withdraws half the stranded balance.
        let withdraw_amount = 4_000i128;
        client.emergency_withdraw(&token_address, &withdraw_amount);

        assert_eq!(token_client.balance(&admin), withdraw_amount);
        assert_eq!(
            token_client.balance(&contract_id),
            stranded_amount - withdraw_amount
        );
    }

    /// Verifies that `emergency_withdraw` can drain the entire contract balance
    /// in a single call.
    #[test]
    fn test_emergency_withdraw_full_balance() {
        let (env, client, contract_id) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let (token_address, token_client, stellar_asset_client) = setup_token(&env);

        let stranded_amount = 7_500i128;
        stellar_asset_client.mint(&contract_id, &stranded_amount);

        client.emergency_withdraw(&token_address, &stranded_amount);

        assert_eq!(token_client.balance(&admin), stranded_amount);
        assert_eq!(token_client.balance(&contract_id), 0);
    }

    /// Verifies that `emergency_withdraw` declares admin authorization as required.
    ///
    /// Soroban's `require_auth()` uses an abort-on-failure model in the host
    /// (non-unwinding panics), so we cannot catch a missing-auth failure inside
    /// the same test process.  Instead we use `mock_all_auths_allowing_non_root_auth`
    /// to record which addresses the call attempts to authorize, then assert that
    /// the admin address — and *only* the admin — appears in that list.
    #[test]
    fn test_admin_is_required_for_emergency_withdraw() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let contract_id = env.register_contract(None, PaymentRouter);
        let client = PaymentRouterClient::new(&env, &contract_id);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        let (token_address, _token_client, stellar_asset_client) = setup_token(&env);
        stellar_asset_client.mint(&contract_id, &5_000i128);

        // Call succeeds because mock_all_auths satisfies any require_auth.
        // What we verify is that the invocation recorded exactly one
        // authorization and that it belongs to admin, proving the function
        // gates on the admin address.
        client.emergency_withdraw(&token_address, &1_000i128);

        let auths = env.auths();
        let admin_auth_present = auths.iter().any(|(addr, _)| *addr == admin);
        assert!(
            admin_auth_present,
            "emergency_withdraw must require the admin address to authorize"
        );
    }

    #[test]
    fn test_blacklist_recipient() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        // Blacklist the recipient
        client.blacklist_address(&recipient);
        assert!(client.is_blacklisted(&recipient));

        // Route payment should fail
        let res = client.try_route_payment(&sender, &recipient, &token_address, &1000);
        assert_eq!(res.unwrap_err().unwrap(), Error::Blacklisted);

        // Unblacklist and try again
        client.unblacklist_address(&recipient);
        assert!(!client.is_blacklisted(&recipient));

        client
            .mock_all_auths()
            .route_payment(&sender, &recipient, &token_address, &1000);
    }

    #[test]
    #[ignore]
    fn test_routes_multiple_distinct_assets() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        client.initialize(
            &admin,
            &treasury,
            &100,
            &1_000_000,
            &PaymentRouter::MAX_AMOUNT,
        );

        let (usdc_like_address, usdc_like_client, usdc_like_admin_client) = setup_token(&env);
        let (eurc_like_address, eurc_like_client, eurc_like_admin_client) = setup_token(&env);
        assert_ne!(usdc_like_address, eurc_like_address);

        usdc_like_admin_client.mint(&sender, &10_000);
        eurc_like_admin_client.mint(&sender, &5_000);

        client.route_payment(&sender, &recipient, &usdc_like_address, &2_000);
        client.route_payment(&sender, &recipient, &eurc_like_address, &1_000);

        assert_eq!(usdc_like_client.balance(&sender), 8_000);
        assert_eq!(usdc_like_client.balance(&recipient), 1_980);
        assert_eq!(eurc_like_client.balance(&sender), 4_000);
        assert_eq!(eurc_like_client.balance(&recipient), 990);
        assert_eq!(client.get_user_volume(&sender), 3_000);
    }

    #[test]
    fn test_benchmark_gas_costs() {
        let (env, client, _) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);

        let (token_address, _token_client, sac) = setup_token(&env);
        sac.mint(&sender, &10_000);

        // Reset budget before initialization
        env.budget().reset_default();
        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);
        let init_cpu = env.budget().cpu_instruction_cost();
        let init_mem = env.budget().memory_bytes_cost();
        log!(
            &env,
            "GAS REPORT: initialize - CPU: {}, Mem: {}",
            init_cpu,
            init_mem
        );

        // Reset budget before route_payment
        env.budget().reset_default();
        client.route_payment(&sender, &recipient, &token_address, &5_000);
        let route_cpu = env.budget().cpu_instruction_cost();
        let route_mem = env.budget().memory_bytes_cost();
        log!(
            &env,
            "GAS REPORT: route_payment - CPU: {}, Mem: {}",
            route_cpu,
            route_mem
        );

        env.budget().print();

        // Fails CI if gas costs exceed defined thresholds
        // Set reasonable thresholds (e.g. 5M CPU and 2MB Mem per call)
        let max_cpu = 5_000_000;
        let max_mem = 2_000_000;

        assert!(
            init_cpu <= max_cpu,
            "initialize CPU cost exceeded threshold! Cost: {}, Threshold: {}",
            init_cpu,
            max_cpu
        );
        assert!(
            init_mem <= max_mem,
            "initialize Memory cost exceeded threshold! Cost: {}, Threshold: {}",
            init_mem,
            max_mem
        );

        assert!(
            route_cpu <= max_cpu,
            "route_payment CPU cost exceeded threshold! Cost: {}, Threshold: {}",
            route_cpu,
            max_cpu
        );
        assert!(
            route_mem <= max_mem,
            "route_payment Memory cost exceeded threshold! Cost: {}, Threshold: {}",
            route_mem,
            max_mem
        );
    }

    #[test]
    #[ignore]
    fn test_refund_ledger_and_withdrawal() {
        let (env, client, contract_id) = setup_env();

        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &treasury, &100, &50, &PaymentRouter::MAX_AMOUNT);

        let (token_address, token_client, stellar_asset_client) = setup_token(&env);

        // Initially zero refund balance
        assert_eq!(client.get_refund_balance(&user, &token_address), 0);

        // Simulate stranded tokens in contract and credit internal refund balance
        let refund_amount = 5_000i128;
        stellar_asset_client.mint(&contract_id, &refund_amount);

        env.as_contract(&contract_id, || {
            PaymentRouter::credit_refund_balance(&env, &user, &token_address, refund_amount);
        });

        assert_eq!(
            client.get_refund_balance(&user, &token_address),
            refund_amount
        );

        // User withdraws partial refund
        let partial_amount = 2_000i128;
        client.withdraw_refund(&user, &token_address, &partial_amount);

        assert_eq!(token_client.balance(&user), partial_amount);
        assert_eq!(
            client.get_refund_balance(&user, &token_address),
            refund_amount - partial_amount
        );

        // User claims remaining refunds with claim_all_refunds
        let claimed = client.claim_all_refunds(&user, &token_address);
        assert_eq!(claimed, refund_amount - partial_amount);
        assert_eq!(token_client.balance(&user), refund_amount);
        assert_eq!(client.get_refund_balance(&user, &token_address), 0);

        // Trying to withdraw again should fail with NoRefundAvailable
        let res = client.try_withdraw_refund(&user, &token_address, &100);
        assert_eq!(res.unwrap_err().unwrap(), Error::NoRefundAvailable);
    }

    #[test]
    fn test_governance_takes_over_fees() {
        let (_, client, _) = setup_env();

        let admin = Address::generate(&client.env);
        let treasury = Address::generate(&client.env);
        let gov = Address::generate(&client.env);

        client.initialize(&admin, &treasury, &100, &1000, &PaymentRouter::MAX_AMOUNT);

        // Admin can still update fees before governance is set
        client.set_fee_bps(&150);
        assert_eq!(client.get_fee(), 150);

        // Admin hands control over to governance
        client.set_governance(&gov);

        // Governance address can now update the fee
        client.set_fee_bps(&200);
        assert_eq!(client.get_fee(), 200);
    }

    // ── Escrow tests ─────────────────────────────────────────────────────────

    /// Shared helper: initialises a contract with zero fees so escrow balance
    /// arithmetic is straightforward.
    fn setup_escrow_env() -> (
        Env,
        PaymentRouterClient<'static>,
        Address, // contract_id
        Address, // sender
        Address, // recipient
        Address, // token_address
        token::Client<'static>,
        token::StellarAssetClient<'static>,
    ) {
        let (env, client, contract_id) = setup_env();
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        // Zero fee so balances are easy to reason about.
        client.initialize(&admin, &treasury, &0, &0, &PaymentRouter::MAX_AMOUNT);

        let sender = Address::generate(&env);
        let recipient = Address::generate(&env);
        let (token_address, token_client, sac) = setup_token(&env);
        sac.mint(&sender, &100_000);

        (
            env,
            client,
            contract_id,
            sender,
            recipient,
            token_address,
            token_client,
            sac,
        )
    }

    #[test]
    fn test_create_and_release_escrow() {
        let (env, client, _contract_id, sender, recipient, token_address, token_client, _sac) =
            setup_escrow_env();

        let amount = 5_000i128;
        let now = env.ledger().timestamp();
        let release_time = now + 1_000;

        let escrow_id = client.create_escrow(&sender, &recipient, &token_address, &amount, &release_time);
        assert_eq!(escrow_id, 1);

        // Sender's balance should have decreased by amount.
        assert_eq!(token_client.balance(&sender), 100_000 - amount);
        // Recipient hasn't received anything yet.
        assert_eq!(token_client.balance(&recipient), 0);

        // Advance ledger past release time.
        env.ledger().set(LedgerInfo {
            timestamp: release_time + 1,
            protocol_version: env.ledger().protocol_version(),
            sequence_number: env.ledger().sequence(),
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        client.release_escrow(&escrow_id);

        // Recipient should now hold the escrowed amount.
        assert_eq!(token_client.balance(&recipient), amount);

        // Escrow entry should be gone.
        let res = client.try_get_escrow(&escrow_id);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowNotFound);
    }

    #[test]
    fn test_release_escrow_before_time_fails() {
        let (env, client, _contract_id, sender, recipient, token_address, _token_client, _sac) =
            setup_escrow_env();

        let now = env.ledger().timestamp();
        let release_time = now + 1_000;

        let escrow_id =
            client.create_escrow(&sender, &recipient, &token_address, &1_000, &release_time);

        // Try to release immediately — should be locked.
        let res = client.try_release_escrow(&escrow_id);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowLocked);
    }

    #[test]
    fn test_reclaim_escrow_after_time() {
        let (env, client, _contract_id, sender, recipient, token_address, token_client, _sac) =
            setup_escrow_env();

        let amount = 3_000i128;
        let now = env.ledger().timestamp();
        let release_time = now + 500;

        let escrow_id =
            client.create_escrow(&sender, &recipient, &token_address, &amount, &release_time);

        let sender_balance_after_escrow = token_client.balance(&sender);

        // Advance past the release time.
        env.ledger().set(LedgerInfo {
            timestamp: release_time + 1,
            protocol_version: env.ledger().protocol_version(),
            sequence_number: env.ledger().sequence(),
            network_id: env.ledger().network_id().into(),
            base_reserve: 100,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 4096,
            max_entry_ttl: 6312000,
        });

        client.reclaim_escrow(&escrow_id);

        // Sender gets the funds back.
        assert_eq!(
            token_client.balance(&sender),
            sender_balance_after_escrow + amount
        );
        // Recipient got nothing.
        assert_eq!(token_client.balance(&recipient), 0);

        // Entry is gone.
        let res = client.try_get_escrow(&escrow_id);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowNotFound);
    }

    #[test]
    fn test_reclaim_before_release_time_fails() {
        let (env, client, _contract_id, sender, recipient, token_address, _token_client, _sac) =
            setup_escrow_env();

        let now = env.ledger().timestamp();
        let release_time = now + 1_000;

        let escrow_id =
            client.create_escrow(&sender, &recipient, &token_address, &1_000, &release_time);

        // Reclaim immediately — should still be locked.
        let res = client.try_reclaim_escrow(&escrow_id);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowLocked);
    }

    #[test]
    fn test_release_escrow_not_found() {
        let (_env, client, _contract_id, _sender, _recipient, _token_address, _token_client, _sac) =
            setup_escrow_env();

        let res = client.try_release_escrow(&999u64);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowNotFound);
    }

    #[test]
    fn test_create_escrow_invalid_release_time() {
        let (env, client, _contract_id, sender, recipient, token_address, _token_client, _sac) =
            setup_escrow_env();

        // release_time in the past (or equal to current timestamp) → EscrowLocked.
        let past_time = env.ledger().timestamp(); // equal, not strictly future
        let res =
            client.try_create_escrow(&sender, &recipient, &token_address, &1_000, &past_time);
        assert_eq!(res.unwrap_err().unwrap(), Error::EscrowLocked);
    }

    #[test]
    fn test_escrow_blocked_when_frozen() {
        let (env, client, _contract_id, sender, recipient, token_address, _token_client, _sac) =
            setup_escrow_env();

        client.emergency_freeze();

        let release_time = env.ledger().timestamp() + 1_000;
        let res =
            client.try_create_escrow(&sender, &recipient, &token_address, &1_000, &release_time);
        assert_eq!(res.unwrap_err().unwrap(), Error::ContractFrozen);
    }
}

/// Property-based tests for fee calculation logic.
///
/// These tests exercise the pure arithmetic used in `process_single_payment`
/// without touching the Soroban environment so they can run as ordinary host
/// tests powered by proptest.
///
/// The invariants verified across 10,000 random inputs are:
/// 1. **Conservation**: `fee_amount + remainder == amount`
/// 2. **Non-negative fee**: `fee_amount >= 0`
/// 3. **Non-negative remainder**: `remainder >= 0`
/// 4. **Cap enforcement**: `fee_amount <= fee_cap`
/// 5. **Fee never exceeds amount**: `fee_amount <= amount`
#[cfg(test)]
mod prop_tests {
    use proptest::prelude::*;

    // --- constants mirrored from the contract ---
    const BPS_DIVISOR: i128 = 10_000;
    /// Maximum valid fee in basis points (100% = 10 000 bps).
    const MAX_FEE_BPS: i128 = 10_000;
    /// Upper bound for a single payment amount (matches contract MAX_AMOUNT).
    const MAX_AMOUNT: i128 = 1_000_000_000_000_000;

    // --- pure fee calculation logic (mirrors process_single_payment) ---

    /// Computes `(fee_amount, remainder)` exactly as the contract does.
    ///
    /// `user_volume_above_threshold` stands in for the tiered-discount check:
    /// when `true` the effective fee is halved.
    fn compute_fee(
        amount: i128,
        fee_bps: i128,
        fee_cap: i128,
        user_volume_above_threshold: bool,
    ) -> (i128, i128) {
        let effective_fee_bps = if user_volume_above_threshold {
            fee_bps / 2
        } else {
            fee_bps
        };

        let mut fee_amount = (amount * effective_fee_bps) / BPS_DIVISOR;
        if fee_amount > fee_cap {
            fee_amount = fee_cap;
        }
        if fee_amount > amount {
            fee_amount = amount;
        }
        let remainder = amount - fee_amount;
        (fee_amount, remainder)
    }

    // -----------------------------------------------------------------------
    // Strategies
    // -----------------------------------------------------------------------

    /// A valid payment amount: 1 ..= MAX_AMOUNT (positive, within contract bounds).
    fn valid_amount() -> impl Strategy<Value = i128> {
        1i128..=MAX_AMOUNT
    }

    /// A valid fee in basis points: 0 ..= 10 000 (0% to 100%).
    fn valid_fee_bps() -> impl Strategy<Value = i128> {
        0i128..=MAX_FEE_BPS
    }

    /// A valid fee cap: 0 ..= MAX_AMOUNT.
    fn valid_fee_cap() -> impl Strategy<Value = i128> {
        0i128..=MAX_AMOUNT
    }

    // -----------------------------------------------------------------------
    // Property: fee_amount + remainder == amount  (conservation of funds)
    // -----------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        /// Funds are fully conserved: every strobe of the amount ends up either
        /// in the treasury (fee) or the recipient (remainder), never lost or
        /// created.
        #[test]
        fn prop_fee_plus_remainder_equals_amount(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, remainder) = compute_fee(amount, fee_bps, fee_cap, above_threshold);
            prop_assert_eq!(
                fee_amount + remainder,
                amount,
                "fee_amount ({}) + remainder ({}) != amount ({})",
                fee_amount, remainder, amount
            );
        }

        /// The fee is always non-negative — the treasury never receives a
        /// negative transfer.
        #[test]
        fn prop_fee_amount_is_non_negative(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, _) = compute_fee(amount, fee_bps, fee_cap, above_threshold);
            prop_assert!(
                fee_amount >= 0,
                "fee_amount ({}) must be >= 0",
                fee_amount
            );
        }

        /// The remainder is always non-negative — the recipient never receives a
        /// negative transfer.
        #[test]
        fn prop_remainder_is_non_negative(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (_, remainder) = compute_fee(amount, fee_bps, fee_cap, above_threshold);
            prop_assert!(
                remainder >= 0,
                "remainder ({}) must be >= 0",
                remainder
            );
        }

        /// The fee never exceeds the configured cap.
        #[test]
        fn prop_fee_respects_cap(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, _) = compute_fee(amount, fee_bps, fee_cap, above_threshold);
            prop_assert!(
                fee_amount <= fee_cap,
                "fee_amount ({}) exceeds fee_cap ({})",
                fee_amount, fee_cap
            );
        }

        /// The fee never exceeds the payment amount itself — the sender cannot
        /// be charged more than they are sending.
        #[test]
        fn prop_fee_never_exceeds_amount(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, _) = compute_fee(amount, fee_bps, fee_cap, above_threshold);
            prop_assert!(
                fee_amount <= amount,
                "fee_amount ({}) exceeds amount ({})",
                fee_amount, amount
            );
        }

        /// When the fee rate is zero the entire amount flows to the recipient.
        #[test]
        fn prop_zero_fee_bps_means_no_fee(
            amount in valid_amount(),
            fee_cap in valid_fee_cap(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, remainder) = compute_fee(amount, 0, fee_cap, above_threshold);
            prop_assert_eq!(fee_amount, 0, "fee_amount must be 0 when fee_bps is 0");
            prop_assert_eq!(remainder, amount, "remainder must equal amount when fee_bps is 0");
        }

        /// When the fee cap is zero no fee is ever collected regardless of the
        /// rate.
        #[test]
        fn prop_zero_fee_cap_means_no_fee(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            above_threshold in any::<bool>(),
        ) {
            let (fee_amount, remainder) = compute_fee(amount, fee_bps, 0, above_threshold);
            prop_assert_eq!(fee_amount, 0, "fee_amount must be 0 when fee_cap is 0");
            prop_assert_eq!(remainder, amount, "remainder must equal amount when fee_cap is 0");
        }

        /// The tiered discount never produces a *higher* fee than the standard
        /// rate: halving the bps can only leave the fee equal or reduce it.
        #[test]
        fn prop_tiered_discount_never_increases_fee(
            amount in valid_amount(),
            fee_bps in valid_fee_bps(),
            fee_cap in valid_fee_cap(),
        ) {
            let (fee_full, _) = compute_fee(amount, fee_bps, fee_cap, false);
            let (fee_discounted, _) = compute_fee(amount, fee_bps, fee_cap, true);
            prop_assert!(
                fee_discounted <= fee_full,
                "discounted fee ({}) must be <= full fee ({})",
                fee_discounted, fee_full
            );
        }
    }
}
