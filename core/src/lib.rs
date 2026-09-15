//! # Cerberus core
//!
//! Cryptographic core of the Cerberus password vault: cipher cascade, key
//! derivation, authentication factors, container format and password generation.
//!
//! Design rationale lives in `docs/SECURITY-DESIGN.md`. The short version:
//! security rests entirely on the user's authentication factors, never on the
//! secrecy of this code.

pub mod cipher;
pub mod container;
pub mod error;
pub mod factors;
pub mod generator;
pub mod kdf;
pub mod porting;
pub mod random;
pub mod session;
pub mod shamir;
pub mod totp;
pub mod vault;

pub use cipher::{Cascade, CipherAlgo};
pub use error::{CoreError, Result};
pub use factors::{Factor, FactorSet, Pattern};
pub use kdf::{KdfParams, MasterKey};
pub use vault::{CustomField, Entry, Folder, Vault};
