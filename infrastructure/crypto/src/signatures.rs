//! Digital Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use crate::keys::{PublicKey, SecretKey};
use crate::challenge::Challenge;
use digest::Digest;
use derive_error::Error;
use crate::common::ByteArrayError;
use core::num::flt2dec::Sign;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    // An invalid challenge was provided
    InvalidChallenge,
}


#[allow(non_snake_case)]
pub struct Signature<P, K> where
    P: PublicKey<K=K>,
    K: SecretKey,
{
    public_nonce: P,
    signature: K,
}

pub trait SchnorrSignature {
    type Scalar: SecretKey;
    type Point: PublicKey<K=Self::Scalar>;

    fn new(public_nonce: Self::Point, signature: Self::Scalar) -> Self;

    fn sign<D: Digest>(secret: &Self::Scalar, nonce: &Self::Scalar, challenge: &Challenge<D>) -> Result<Self,
        SignatureError>;

    /// Check whether the given signature is valid for the given message and public key
    fn verify<D: Digest>(&self, public_key: &Self::Point, challenge: &Challenge<D>) -> bool;

    fn get_signature(&self) -> &Self::Scalar;

    fn get_public_nonce(&self) -> &Self::Point;
}


impl<P, K> SchnorrSignature for Signature<P, K>
    where
        P: PublicKey<K=K>,
        K: SecretKey,
{
    type Scalar = K;
    type Point = P;

    fn new(public_nonce: Self::Point, signature: Self::Scalar) -> Self {
        Signature { public_nonce, signature }
    }

    fn sign<D: Digest>(secret: &Self::Scalar, nonce: &Self::Scalar, challenge: &Challenge<D>) -> Result<Self,
        SignatureError> {
        // s = r + e.k
        let e = match Self::Scalar::from_vec(&challenge.hash()) {
            Ok(e) => e,
            Err(_) => return Err(SignatureError::InvalidChallenge),
        };
        let s = &nonce + &(&secret * &e);
        let public_nonce = Self::Point::from_secret_key(nonce);
        Some(Self::new(public_nonce, s))
    }

    fn verify<D: Digest>(&self, public_key: &Self::Point, challenge: &Challenge<D>) -> bool {
        unimplemented!()
    }

    fn get_signature(&self) -> &Self::Scalar {
        unimplemented!()
    }

    fn get_public_nonce(&self) -> &Self::Point {
        unimplemented!()
    }
}
