//! Digital Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use crate::keys::{PublicKey, SecretKey};

/// Generic definition of Schnorr Signature functionality, agnostic of the elliptic curve used.
/// Schnorr signatures are linear and have the form _s = r + ek_, where _r_ is a nonce (secret key),
/// _k_ is a secret key, and _s_ is the signature.
#[allow(non_snake_case)]
pub trait SchnorrSignature {
    type Scalar: SecretKey;
    type Point: PublicKey;
    type Challenge;

    fn new(public_nonce: Self::Point, signature: Self::Scalar) -> Self;

    fn sign(secret: &Self::Scalar, nonce: &Self::Scalar, challenge: Self::Challenge) -> Self;

    /// Check whether the given signature is valid for the given message and public key
    fn verify(&self, public_key: &Self::Point, challenge: &Self::Challenge) -> bool;

    fn get_signature(&self) -> &Self::Scalar;

    fn get_public_nonce(&self) -> &Self::Point;

    /// An adaptor signature is one that retains a piece of information, making it incomplete. Once some condition is
    /// satisfied (e.g. another payment is received) the piece of information can be revealed, yielding a final signature.
    /// The adaptor signature makes use of another keypair, \\( T = t.G \\) in addition to the usual nonce and private
    /// key pairs from the [SchnorrSignature](Trait.SchnorrSignature.html).
    fn adapt_signature(&self, t: &Self::Scalar) -> Self {
        let s_adapt = self.get_signature() - t;
        let r_adapt = self.get_public_nonce() + Self::Point::from_secret_key(&t);
        Self::new(r_adapt, s_adapt)
    }
}



