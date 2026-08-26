# Provable Fairness System

> A standalone, open-source implementation of a provably fair winner selection system on Solana.

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Anchor](https://img.shields.io/badge/Anchor-0.30.1-purple.svg)](https://www.anchor-lang.com/)
[![Solana](https://img.shields.io/badge/Solana-1.18-blue.svg)](https://solana.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📖 Overview

**Provable Fairness System** is a complete, production-ready implementation of a commit-reveal protocol with Merkle tree verification on Solana. It enables transparent, verifiable random selection without requiring trust in the organizer.

Unlike traditional giveaways where the organizer controls the outcome, this system uses on-chain randomness (Solana slot hashes) and cryptographic commitments to ensure complete transparency and verifiability.

---

## 🎯 Key Features

### 🔐 Cryptographic Guarantees

| Feature | Description |
|---------|-------------|
| **Commit-Reveal Protocol** | Prevents manipulation by committing to participants before randomness is known |
| **Merkle Tree Verification** | Compact on-chain storage with independently verifiable proofs |
| **Unpredictable Randomness** | Uses Solana slot hashes that cannot be predicted in advance |
| **Deterministic Selection** | Anyone can re-run the algorithm and verify winners |
| **Tamper-Proof Results** | Winner root stored on-chain, immutable after reveal |

### 📦 What's Included

- Complete Anchor program with 8 instructions
- Core cryptographic algorithms (Fisher-Yates, Merkle trees, randomness derivation)
- Comprehensive integration tests
- Fee verification system
- Account management with reallocation
- PDA-based account derivation

---

## 🔄 How It Works

### The Commit-Reveal Protocol

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMMIT-REVEAL PROTOCOL                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. CREATE                                                      │
│     ┌──────────────────────────────────────────────────┐       │
│     │ • Organizer builds participant list              │       │
│     │ • Creates Merkle tree                            │       │
│     │ • Stores Merkle root on-chain                   │       │
│     └──────────────────────────────────────────────────┘       │
│                              │                                   │
│                              ▼                                   │
│  2. COMMIT                                                      │
│     ┌──────────────────────────────────────────────────┐       │
│     │ • Records current Solana slot                    │       │
│     │ • Sets reveal slot = commit + 150               │       │
│     │ • State transitions: created → committed         │       │
│     └──────────────────────────────────────────────────┘       │
│                              │                                   │
│                              ▼                                   │
│  3. WAIT (~60 seconds)                                         │
│     ┌──────────────────────────────────────────────────┐       │
│     │ • Future slot hash cannot be predicted           │       │
│     │ • No human intervention possible                 │       │
│     └──────────────────────────────────────────────────┘       │
│                              │                                   │
│                              ▼                                   │
│  4. REVEAL                                                      │
│     ┌──────────────────────────────────────────────────┐       │
│     │ • Keeper fetches slot hash from commit slot      │       │
│     │ • Derives randomness: Keccak(slot_hash || root)  │       │
│     │ • Selects winners via Fisher-Yates               │       │
│     │ • Stores winner Merkle root                     │       │
│     │ • State transitions: committed → drawn           │       │
│     └──────────────────────────────────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Randomness Derivation

```rust
// Anyone can verify the randomness was derived correctly
fn derive_randomness(slot_hash: &[u8; 32], participant_root: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(slot_hash);      // Unpredictable
    combined[32..].copy_from_slice(participant_root); // Tied to participants
    keccak256(&combined)                           // Deterministic
}
```

### Winner Selection (Fisher-Yates)

```rust
fn select_winner_indices(randomness: &[u8; 32], count: u64, winners: u64) -> Vec<u64> {
    // Deterministic Fisher-Yates shuffle
    // Anyone can re-run with the same randomness and verify
}
```

---

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+
- Solana CLI 1.18+
- Anchor 0.30.1+

### Installation

```bash
# Clone the repository
git clone https://github.com/Neontoshi/provable-fairness-system
cd provable-fairness-system
```

### Build

```bash
anchor build
```

### Test

```bash
anchor test
```

### Deploy (Devnet)

```bash
anchor deploy --provider.cluster devnet
```

---

## 📚 Program Instructions

| Instruction | Description | State Transition |
|-------------|-------------|------------------|
| `initialize_user` | Create a user state account | - |
| `create_user_account` | Create a giveaway account | - |
| `create_giveaway` | Create a new giveaway | → Created |
| `create_and_commit_giveaway` | Create + commit in one tx | → Committed |
| `commit_draw` | Commit a draw | Created → Committed |
| `reveal_draw` | Reveal winners | Committed → Drawn |
| `cancel_giveaway` | Cancel a giveaway | → Cancelled |
| `close_user_account` | Reclaim rent | - |

---

## 🔍 Verification

Anyone can independently verify a giveaway:

### 1. Fetch On-Chain Data
```bash
solana account <GIVEAWAY_PDA> --output json
```

### 2. Rebuild Merkle Tree
Use the same algorithm as the program to build the participant Merkle tree.

### 3. Derive Randomness
```rust
let slot_hash = get_slot_hash(commit_slot);
let randomness = derive_randomness(&slot_hash, &participant_root);
```

### 4. Run Selection
```rust
let winners = select_winner_indices(&randomness, participant_count, winner_count);
```

### 5. Compare Results
Verify the computed winner root matches the on-chain `winner_root`.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER ACCOUNTS                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  UserState                                              │   │
│  │  • authority: Pubkey                                    │   │
│  │  • total_accounts: u64                                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  UserGiveaways (per account)                           │   │
│  │  • authority: Pubkey                                    │   │
│  │  • account_index: u64                                   │   │
│  │  • giveaways: Vec<GiveawayData>                         │   │
│  │  • giveaway_count: u64                                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  GiveawayData (per giveaway)                           │   │
│  │  • participant_root: [u8; 32]   (Merkle root)           │   │
│  │  • participant_count: u64                               │   │
│  │  • winner_count: u64                                    │   │
│  │  • state: u8            (0=created, 1=committed,        │   │
│  │  • commit_slot: u64      2=drawn, 3=cancelled)          │   │
│  │  • reveal_slot: u64                                     │   │
│  │  • winner_root: [u8; 32]   (Winner Merkle root)         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `REVEAL_DELAY_SLOTS` | 150 | ~60 seconds wait between commit and reveal |
| `MAX_PARTICIPANTS` | 100,000 | Maximum participants per giveaway |
| `MAX_WINNERS` | 10,000 | Maximum winners per giveaway |
| `MAX_REVEAL_WINDOW` | 450 | Maximum slots before slot hash expires |
| `MAX_ACCOUNTS_PER_USER` | 100 | Maximum accounts per user |
| `MAX_DISPLAYED_WINNERS` | 6 | Winners shown in the reveal event |

---

## 🔒 Security

### Trust Assumptions

- **Solana consensus** is correct and available
- **Slot hashes** are unpredictable (relies on Solana)
- **Treasury address** is secure
- **Keeper address** is controlled by the platform

### Attack Vectors & Mitigations

| Attack | Mitigation |
|--------|------------|
| Front-running | 150-slot delay makes prediction infeasible |
| Participant manipulation | Merkle root stored before randomness known |
| Randomness manipulation | Slot hash cannot be predicted |
| Results tampering | Winner root stored immutably |
| Fee evasion | On-chain fee verification |
| Rent exhaustion | Realloc with payer covers costs |

---

## 🧪 Testing

```bash
# Run all tests
anchor test

# Run specific test
cargo test test_commit_reveal_flow -- --nocapture

# Run with logging
RUST_LOG=solana_program_test=debug anchor test
```

### Test Coverage

- ✅ Utility functions (randomness, selection, fees)
- ✅ Full commit-reveal flow
- ✅ State transitions
- ✅ Edge cases (zero participants, max limits)
- ✅ Error conditions (too early, expired, invalid state)
- ✅ Multiple giveaways per account
- ✅ Fee verification
- ✅ Account closure

---

## 📝 License

MIT License - Free for commercial and open-source use.

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## 🙏 Acknowledgments

- Built with [Anchor](https://www.anchor-lang.com/)
- Powered by [Solana](https://solana.com/)
- Inspired by the need for transparent, verifiable randomness

---

## 📞 Support

- 📧 Email: [daisisamuel23@gmail.com]
- 🐦 Twitter: [@Neontoshi]
- 💬 Discord: [Neontoshi]

---

**Built with ❤️ for provably fair systems on Solana.**
