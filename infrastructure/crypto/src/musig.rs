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
};
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
    participants: Vec<P>,
}

impl<K, P> JointKey<P>
where
    K: SecretKey + Mul<P, Output = P>,
    P: PublicKey<K = K>,
{
    pub fn new() -> JointKey<P> {
        JointKey { participants: Vec::new() }
    }

    pub fn add(&mut self, pub_key: P) {
        self.participants.push(pub_key);
    }

    pub fn add_keys<T: Iterator<Item = P>>(&mut self, keys: T) {
        for k in keys {
            self.add(k);
        }
    }

    ///Utility function to calculate \\( \ell = H(P_1 || ... || P_n) \mod p \\)
    pub fn calculate_common<D: Digest>(&self) -> K {
        let mut common = Challenge::<D>::new();
        for k in self.participants.iter() {
            common = common.concat(k.to_bytes());
        }
        K::from_vec(&common.hash()).expect("Could not calculate Scalar from hash value. Your crypto/hash combination \
        might be inconsistent")
    }

    /// Private utility function to calculate \\( H(\ell || P_i) \mod p \\)
    fn calculate_partial_key<D: Digest>(common: &[u8], pubkey: &P) -> K {
        let k = Challenge::<D>::new()
            .concat(common)
            .concat(pubkey.to_bytes())
            .hash();
        K::from_vec(&k).expect("Could not calculate Scalar from hash value. Your crypto/hash combination might be inconsistent")
 }

    pub fn sort_keys(&mut self) {
        self.participants.sort_unstable();
    }

    /// Utility function that produces the vector of MuSig private key modifiers, \\( a_i = H(\ell || P_i) \\)
    pub fn calculate_musig_scalars<D: Digest>(&self) -> Vec<K> {
        let common = self.calculate_common::<D>();
        self.participants.iter().map(|p| JointKey::calculate_partial_key::<D>(common.to_bytes(), p)).collect()
    }

    /// Calculate the value of the Joint MuSig public key. **NB**: you should ensure that the public keys are in
    /// canonical order, or else call `sort_keys()` before calculating the joint key.
    pub fn calculate_joint_key<D: Digest>(&mut self) -> P {
        let s = self.calculate_musig_scalars::<D>();
        let key = P::batch_mul(&s, &self.participants);
        key
    }
}
