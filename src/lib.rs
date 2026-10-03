//! Tachi-flow: on-chain BTC ↔ Tachi VTXO liquidity engine (bounty #10 PoC).

pub mod advance;
pub mod api;
pub mod bond;
pub mod engine;
pub mod error;
pub mod events;
pub mod faucet;
pub mod htlc;
pub mod lightning;
pub mod model;
pub mod store;
pub mod tachi;
pub mod tachi_tx;
pub mod vault;
pub mod watch;

pub use engine::Engine;
pub use error::Error;
pub use model::{Side, SwapStatus};
