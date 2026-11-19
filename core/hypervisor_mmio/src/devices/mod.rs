//! Virtual hardware devices for the PS5 platform.

pub mod ipc;
pub mod kraken;
pub mod storage;

pub use ipc::IpcMailbox;
pub use kraken::{KrakenDmaEngine, OodleAlgorithm};
pub use storage::Ps5StorageController;
