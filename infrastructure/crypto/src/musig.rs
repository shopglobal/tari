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
    keys::{PublicKey, SecretKey},
};
use std::prelude::v1::Vec;
use crate::challenge::Challenge;
use digest::Digest;
use std::ops::Mul;
use std::clone::Clone;

/// The JointKey is a modified public key used in Signature aggregation schemes like MuSig which is not susceptible
/// to Rogue Key attacks.
///
/// A joint key is calculated from _n_ participants by having each of them calculate:
/// $$
///   L = H(P_1 || P_2 || \dots || P_n)
///   X = \sum H(L || P_i)P_i
///   X_i = k_i H(L || P_i).G
/// $$
pub struct JointKey<P: PublicKey> {
    participants: Vec<P>,
}

impl<K, P> JointKey<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K = K>, {

    pub fn new() -> JointKey<P> {
        JointKey {
            participants: Vec::new(),
        }
    }

    pub fn add(mut self, pub_key: P) -> Self {
        self.participants.push(pub_key);
        self
    }

    pub fn add_keys<T: Iterator<Item = P>>(mut self, keys: T) -> Self {
        let mut this = self;
        for k in keys {
            this = this.add(k);
        }
        this
    }

    fn calculate_common<D: Digest>(&self) -> Vec<u8> {
        let mut common = Challenge::<D>::new();
        for k in self.participants.iter() {
            common = common.concat(k.to_bytes());
        }
        common.hash()
    }

    pub fn calculate_joint_key<D: Digest>(&self) -> P {
        unimplemented!()
    }

    pub fn calculate_partial_key<D: Digest>(&self, i: usize) -> Option<P> {
        let common = self.calculate_common::<D>();
        let challenge = Challenge::<D>::new();
        let key = match self.participants.get(i) {
            None => return None,
            Some(p) => (*p).clone()
        };
        let partial = challenge
            .concat(&common)
            .concat(key.to_bytes())
            .hash();
        let scalar = K::from_vec(&partial).unwrap();
        Some(K::mul(scalar, key))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_joint_key_creation() {
//        let joint_key = JointKey::new();
//        joint_key
//            .add(pubkey_1)
//            .add(pubkey_2);
//
//        joint_key.add_keys(keys);
//        let X = joint_key.calculate_joint_key();
//        let Xi = joint_key.calculate_partial_key(i);
//        let partials = joint_key.partials();

    }
}