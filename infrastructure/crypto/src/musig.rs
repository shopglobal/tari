// Copyright 2019 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

use crate::{
    challenge::Challenge,
    keys::{PublicKey, SecretKey},
    signatures::SchnorrSignature,
};
use derive_error::Error;
use digest::Digest;
use std::{ops::Mul, prelude::v1::Vec};

/// The JointKey is a modified public key used in Signature aggregation schemes like MuSig which is not susceptible
/// to Rogue Key attacks.
///
/// A joint key is calculated from _n_ participants by having each of them calculate:
/// $$
///   L = H(P_1 || P_2 || \dots || P_n)
///   X = \sum H(L || P_i)P_i
///   X_i = k_i H(L || P_i).G
/// $$
/// Concrete implementations of JointKey will also need to implement the MultiScalarMul trait, which allows them to
/// provide implementation-specific optimisations for dot-product operations.
pub struct JointKey<P: PublicKey> {
    is_sorted: bool,
    participants: Vec<P>,
}

impl<K, P> JointKey<P>
where
    K: SecretKey + Mul<P, Output = P>,
    P: PublicKey<K = K>,
{
    /// Create a new JointKey instance containing no participant keys
    pub fn new() -> JointKey<P> {
        JointKey { is_sorted: false, participants: Vec::new() }
    }

    /// If the participant keys are in lexicographical order, returns true.
    pub fn is_sorted(&self) -> bool {
        self.is_sorted
    }

    /// Add a participant signer's public key to the JointKey
    pub fn add(&mut self, pub_key: P) {
        self.participants.push(pub_key);
        self.is_sorted = false;
    }

    /// Add all the keys in `keys` to the participant list.
    pub fn add_keys<T: IntoIterator<Item = P>>(&mut self, keys: T) {
        for k in keys.into_iter() {
            self.add(k);
        }
    }

    /// Utility function to calculate \\( \ell = H(P_1 || ... || P_n) \mod p \\)
    /// # Panics
    /// If the SecretKey implementation cannot construct a valid key from the given hash, the function will panic.
    /// You should ensure that the SecretKey constructor protects against failures and that the hash digest given
    /// produces a byte array of the correct length.
    pub fn calculate_common<D: Digest>(&self) -> K {
        let mut common = Challenge::<D>::new();
        for k in self.participants.iter() {
            common = common.concat(k.to_bytes());
        }
        K::from_vec(&common.hash())
            .expect("Could not calculate Scalar from hash value. Your crypto/hash combination might be inconsistent")
    }

    /// Private utility function to calculate \\( H(\ell || P_i) \mod p \\)
    /// # Panics
    /// If the SecretKey implementation cannot construct a valid key from the given hash, the function will panic.
    /// You should ensure that the SecretKey constructor protects against failures and that the hash digest given
    /// produces a byte array of the correct length.
    fn calculate_partial_key<D: Digest>(common: &[u8], pubkey: &P) -> K {
        let k = Challenge::<D>::new().concat(common).concat(pubkey.to_bytes()).hash();
        K::from_vec(&k)
            .expect("Could not calculate Scalar from hash value. Your crypto/hash combination might be inconsistent")
    }

    /// Sort the keys in the participant list. The order is determined by the `Ord` trait of the concrete public key
    /// implementation used to construct the joint key.
    /// **NB:** Sorting the keys will, usually, change the value of the joint key!
    pub fn sort_keys(&mut self) {
        self.participants.sort_unstable();
        self.is_sorted = true;
    }

    /// Utility function that produces the vector of MuSig private key modifiers, \\( a_i = H(\ell || P_i) \\)
    pub fn calculate_musig_scalars<D: Digest>(&self) -> Vec<K> {
        let common = self.calculate_common::<D>();
        self.participants.iter().map(|p| JointKey::calculate_partial_key::<D>(common.to_bytes(), p)).collect()
    }

    /// Calculate the value of the Joint MuSig public key. **NB**: you should usually sort the participant's keys
    /// before calculating the joint key.
    pub fn calculate_joint_key<D: Digest>(&mut self) -> P {
        let s = self.calculate_musig_scalars::<D>();
        let key = P::batch_mul(&s, &self.participants);
        key
    }

    /// Return the index of the given key in the joint key participants list, or None if it isn't in the list
    pub fn index_of(&self, pubkey: &P) -> Result<usize, MuSigError> {
        println!(
            "Participants: {:?}\n SearchFor: {:?}",
            self.participants.iter().map(|p| p.to_hex()).collect::<String>(),
            pubkey.to_hex()
        );
        if !self.is_sorted {
            return Err(MuSigError::NotSorted);
        }
        match self.participants.binary_search(pubkey) {
            Ok(i) => Ok(i),
            Err(_) => Err(MuSigError::ParticipantNotFound),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuSigError {
    // The number of public nonces must match the number of public keys in the joint key
    MismatchedNonces,
    // The number of partial signatures must match the numer of public keys in the joint key
    MismatchedSignatures,
    // The aggregate signature did not verify
    InvalidSignature,
    // The participant list must be sorted before making this call
    NotSorted,
    // The participant key is not in the list
    ParticipantNotFound,
}

/// MuSig signature aggregation. [MuSig](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)
/// is a 3-round signature aggregation protocol.
/// 1. In the first round, participants share their public keys. From this set of keys, a
/// [Joint Public Key](structs.JointKey.html) is constructed by all participants.
/// 2. Participants then share a public nonce, \\( R_i \\), and all participants calculate the shared nonce,
///   \\( R = \sum R_i \\).
/// 3. Each participant then calculates a partial signature, with the final signature being the sum of all the
/// partial signatures.
///
/// The `MuSig` struct facilitates the management of rounds 2 and 3. Use [JointKey](structs.JointKey.html) to manage
/// Round 1.
pub struct MuSig<P: PublicKey> {
    joint_key: JointKey<P>,
    public_nonces: Vec<P>,
}

impl<K, P> MuSig<P>
where
    K: SecretKey + Mul<P, Output = P>,
    P: PublicKey<K = K>,
{
    fn new(joint_key: JointKey<P>) -> MuSig<P> {
        unimplemented!()
    }

    fn add_public_nonce(r: P) {}

    fn add_partial_signature(s: K) {}

    fn calculate_my_partial_signature<S>(nonce: &K, secret: &K) -> S
    where S: SchnorrSignature<Point = P, Scalar = K> {
        unimplemented!()
    }

    fn calculate_agg_sig<S>() -> Result<S, MuSigError>
    where S: SchnorrSignature<Point = P, Scalar = K> {
        unimplemented!()
    }

    fn verify_signature() -> bool {
        unimplemented!()
    }
}
