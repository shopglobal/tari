//! Digital Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use crate::{
    challenge::Challenge,
    keys::{PublicKey, SecretKey},
};
use derive_error::Error;
use digest::Digest;
use std::ops::{Add, Mul};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchnorrSignatureError {
    // An invalid challenge was provided
    InvalidChallenge,
}

#[allow(non_snake_case)]
#[derive(PartialEq, Eq, Copy, Debug, Clone)]
pub struct SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    public_nonce: P,
    signature: K,
}

impl<P, K> SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    pub fn new(public_nonce: P, signature: K) -> Self {
        SchnorrSignature { public_nonce, signature }
    }

    pub fn calc_signature_verifier(&self) -> P {
        P::from_secret_key(&self.signature)
    }

    pub fn sign<'a, 'b, D: Digest>(
        secret: K,
        nonce: K,
        challenge: Challenge<D>,
    ) -> Result<Self, SchnorrSignatureError>
    where
        K: Add<Output = K> + Mul<P, Output = P> + Mul<Output = K>,
    {
        // s = r + e.k
        let e = match K::from_vec(&challenge.hash()) {
            Ok(e) => e,
            Err(_) => return Err(SchnorrSignatureError::InvalidChallenge),
        };
        let public_nonce = P::from_secret_key(&nonce);
        let ek = e * secret;
        let s = ek + nonce;
        Ok(Self::new(public_nonce, s))
    }

    pub fn verify<'a, D: Digest>(&self, public_key: &'a P, challenge: Challenge<D>) -> bool
    where K: Mul<&'a P, Output = P> {
        let lhs = self.calc_signature_verifier();
        let e = match K::from_vec(&challenge.hash()) {
            Ok(e) => e,
            Err(_) => return false,
        };
        let rhs = self.public_nonce.clone() + e * public_key;
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    #[inline]
    pub fn get_signature(&self) -> &K {
        &self.signature
    }

    #[inline]
    pub fn get_public_nonce(&self) -> &P {
        &self.public_nonce
    }
}

impl<'a, 'b, P, K> Add<&'b SchnorrSignature<P, K>> for &'a SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
{
    type Output = SchnorrSignature<P, K>;

    fn add(self, rhs: &'b SchnorrSignature<P, K>) -> SchnorrSignature<P, K> {
        let r_sum = self.get_public_nonce() + rhs.get_public_nonce();
        let s_sum = self.get_signature() + rhs.get_signature();
        SchnorrSignature::new(r_sum, s_sum)
    }
}
