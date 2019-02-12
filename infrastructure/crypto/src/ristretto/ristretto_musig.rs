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

#[cfg(test)]
mod test {
    use crate::{
        challenge::Challenge,
        common::ByteArray,
        musig::JointKey,
        ristretto::{test_common::*, RistrettoSecretKey},
    };
    use sha2::Sha256;

    fn hash_pair(v1: &[u8], v2: &[u8]) -> RistrettoSecretKey {
        let k = Challenge::<Sha256>::new().concat(v1).concat(v2).hash();
        RistrettoSecretKey::from_vec(&k).unwrap()
    }

    /// Test the steps in the MuSig Joint Public key construction. We don't sort the keys in this test because we
    /// want to keep the order of the keys consistent
    #[test]
    pub fn musig_joint_key() {
        let (_, p1) = get_keypair();
        let (_, p2) = get_keypair();
        let mut jk = JointKey::new();
        jk.add(p1);
        jk.add(p2);
        let s: Vec<RistrettoSecretKey> = jk.calculate_musig_scalars::<Sha256>();
        let ell = hash_pair(p1.to_bytes(), p2.to_bytes());
        assert_eq!(ell, jk.calculate_common::<Sha256>(), "Ell is not equal");
        let a1 = hash_pair(ell.to_bytes(), p1.to_bytes());
        let a2 = hash_pair(ell.to_bytes(), p2.to_bytes());
        assert_eq!(a1, s[0], "a1 is not equal");
        assert_eq!(a2, s[1], "a2 is not equal");
        let jk = jk.calculate_joint_key::<Sha256>();
        assert_eq!(jk, a1 * p1 + a2 * p2);
    }

    #[test]
    fn joint_key_iterator() {
        let (_, p1) = get_keypair();
        let (_, p2) = get_keypair();
        let (_, p3) = get_keypair();
        let mut jk1 = JointKey::new();
        let mut jk2 = JointKey::new();
        jk2.add(p1.clone());
        jk2.add(p2.clone());
        jk2.add(p3.clone());
        let v = vec![p1, p2, p3].into_iter();
        jk1.add_keys(v);
        assert_eq!(jk1.calculate_joint_key::<Sha256>(), jk2.calculate_joint_key::<Sha256>());
    }
}
