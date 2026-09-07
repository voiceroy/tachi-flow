//! Tachi-flow: on-chain BTC ↔ Tachi VTXO liquidity engine (bounty #10 PoC).

pub mod api;
pub mod engine;
pub mod error;
pub mod htlc;
pub mod model;
pub mod tachi;
pub mod tachi_tx;

pub use engine::Engine;
pub use error::Error;
pub use model::{Side, SwapStatus};
