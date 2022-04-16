#![no_std]

//! This crate implements RustCrypto traits on top of the `pqcrypto` crate. It exposes all the
//! functionality of `pqcrypto` as well.
//!
//! The signature schemes implement `Signer`, `Verifier`, and `Signature` from RustCrypto's
//! `signature` crate.
//!
//! The KEMs implement `Encapsulator`, `Decapsulator`, and `EncappedKey` from RustCrypto's `kem`
//! crate.

pub mod kem;
pub mod sign;
