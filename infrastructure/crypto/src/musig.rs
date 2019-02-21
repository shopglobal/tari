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
use crate::challenge::MessageHash;
use std::collections::HashMap;

//----------------------------------------------   Constants       ------------------------------------------------//
const MAX_SIGNATURES: usize = 32768; // If you need more, call customer support

//----------------------------------------------   Error Codes     ------------------------------------------------//
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuSigError {
    // The number of public nonces must match the number of public keys in the joint key
    MismatchedNonces,
    // The number of partial signatures must match the number of public keys in the joint key
    MismatchedSignatures,
    // The aggregate signature did not verify
    InvalidSignature,
    // The participant list must be sorted before making this call
    NotSorted,
    // The participant key is not in the list
    ParticipantNotFound,
    // An attempt was made to perform an invalid MuSig state transition
    InvalidStateTransition,
    // An attempt was made to add a duplicate public key to a MuSig signature
    DuplicatePubKey,
    // There are too many parties in the MuSig signature
    TooManyParticipants,
}

//----------------------------------------------     Joint Key     ------------------------------------------------//

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
    num_signers: usize,
    is_sorted: bool,
    participants: Vec<P>,
}

impl<K, P> JointKey<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    /// Create a new JointKey instance containing no participant keys, or return `TooManyParticipants` if n exceeds
    /// `MAX_SIGNATURES`
    pub fn new(n: usize) -> Result<JointKey<P>, MuSigError> {
        if n > MAX_SIGNATURES {
            return Err(MuSigError::TooManyParticipants)
        }
        Ok(JointKey {
            is_sorted: false,
            participants: Vec::with_capacity(n),
            num_signers: n
        })
    }

    /// If the participant keys are in lexicographical order, returns true.
    pub fn is_sorted(&self) -> bool {
        self.is_sorted
    }

    /// The number of parties in the MuSig protocol
    pub fn num_signers(&self) -> usize {
        self.num_signers
    }

    /// Add a participant signer's public key to the JointKey
    pub fn add_key(&mut self, pub_key: P) -> Result<usize, MuSigError> {
        if self.key_exists(&pub_key) {
            return Err(MuSigError::DuplicatePubKey);
        }
        // push panics on int overflow, so catch this here
        let n = self.participants.len();
        if n + 1 >= MAX_SIGNATURES {
            return Err(MuSigError::TooManyParticipants);
        }
        self.participants.push(pub_key);
        self.is_sorted = false;
        Ok(n + 1)
    }

    /// Checks whether the given public key is in the participants list
    pub fn key_exists(&self, key: &P) -> bool {
        self.participants.iter().any(|v| v == key)
    }

    /// Add all the keys in `keys` to the participant list.
    pub fn add_keys<T: IntoIterator<Item=P>>(&mut self, keys: T) -> Result<usize, MuSigError> {
        for k in keys.into_iter() {
            self.add_key(k)?;
        }
        Ok(self.participants.len())
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

    /// Return the index of the given key in the joint key participants list. If the list isn\t sorted, returns
    /// Err(`NotSorted`), and if the key isn't in the list, returns `Err(ParticipantNotFound)`
    pub fn index_of(&self, pubkey: &P) -> Result<usize, MuSigError> {
        if !self.is_sorted {
            return Err(MuSigError::NotSorted);
        }
        match self.participants.binary_search(pubkey) {
            Ok(i) => Ok(i),
            Err(_) => Err(MuSigError::ParticipantNotFound),
        }
    }
}

//----------------------------------------------      MuSig        ------------------------------------------------//

/// MuSig signature aggregation. [MuSig](https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)
/// is a 3-round signature aggregation protocol.
/// We assume that all the public keys are known and publicly accessible. A [Joint Public Key](structs.JointKey.html)
/// is constructed by all participants.
/// 1. In the first round, participants share the hash of their nonces.
/// 2. Participants then share their public nonce, \\( R_i \\), and all participants calculate the shared nonce,
///   \\( R = \sum R_i \\).
/// 3. Each participant then calculates a partial signature, with the final signature being the sum of all the
/// partial signatures.
///
/// This protocol is implemented as a Finite State Machine. MuSig is a simple wrapper around a `MusigState` enum that
/// holds the various states that the MuSig protocol can be in, combined with a `MuSigEvents` enum that enumerates
/// the relevant input events that can  occur. Any attempt to invoke an invalid transition, or any other failure
/// condition results in the `Failure` state; in which case the MuSig protocol should be abandoned.
///
/// Rust's type system is leveraged to prevent any rewinding of state; old state variables are destroyed when
/// transitioning to new states. The MuSig variable also _takes ownership_ of the nonce key, reducing the risk of
/// nonce reuse (though obviously it doesn't eliminate it). Let's be clear: REUSING a nonce WILL result in your secret
/// key being discovered. See
/// [this post](https://tlu.tarilabs.com/cryptography/digital_signatures/introduction_schnorr_signatures.html#musig)
/// for details.
pub struct MuSig<P: PublicKey> {
    state: MuSigState<P>,
}

impl<K, P> MuSig<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    pub fn new(n: usize) -> MuSig<P> {
        let state = match Initialization::new(n) {
            Ok(s) => MuSigState::Initialization(s),
            Err(e) => MuSigState::Failed(e),
        };
        MuSig { state }
    }

    fn invalid() -> MuSigState<P> {
        MuSigState::Failed(MuSigError::InvalidStateTransition)
    }

    /// Implement a finite state machine. Each combination of State and Event is handled here; for each combination, a
    /// new state is determined, consuming the old one. If `MuSigState::Failed` is ever returned, the protocol must be
    /// abandoned.
    pub fn handle_event(mut self, event: MuSigEvent<P>) -> Self {
        let new_state = match (self.state, event) {
            // On initialization, you can add keys until you reach `num_signers` at which point the state
            // automatically flips to `NonceHashCollection`
            (MuSigState::Initialization(s), MuSigEvent::AddKey(p)) => s.add_pubkey(p),
            (MuSigState::Initialization(_), _) => MuSig::invalid(),
            // Nonce Hash collection
            (MuSigState::NonceHashCollection(s), MuSigEvent::AddNonceHash(p, h)) => s.add_nonce_hash(p, h),
            (MuSigState::NonceHashCollection(_), _) => MuSig::invalid(),
            // There's no way back from a Failed State.
            (MuSigState::Failed(_), _) => MuSig::invalid(),
            _ => MuSig::invalid(),
        };
        self.state = new_state;
        self
    }
}

//-------------------------------------------  MuSig State Definitions ---------------------------------------------//

pub enum MuSigEvent<'a, P: PublicKey> {
    AddKey(P),
    AddNonceHash(&'a P, MessageHash),
    AddNonce,
    AddPartialSig,
}

enum MuSigState<P: PublicKey> {
    Initialization(Initialization<P>),
    NonceHashCollection(NonceHashCollection<P>),
    NonceCollection,
    SignatureCollection,
    Finalized,
    Failed(MuSigError),
}

struct Initialization<P: PublicKey> {
    joint_key: JointKey<P>,
}

impl<P, K> Initialization<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    pub fn new(n: usize) -> Result<Initialization<P>, MuSigError> {
        let joint_key = JointKey::new(n)?;
        Ok(Initialization { joint_key })
    }

    pub fn add_pubkey(mut self, key: P) -> MuSigState<P> {
        match self.joint_key.add_key(key) {
            Ok(n) => {
                if n == self.joint_key.num_signers() {
                    MuSigState::NonceHashCollection(NonceHashCollection::new(self))
                } else {
                    self.joint_key.sort_keys();
                    MuSigState::Initialization(self)
                }
            }
            Err(e) => MuSigState::Failed(e),
        }
    }
}

struct NonceHashCollection<P: PublicKey> {
    joint_key: JointKey<P>,
    nonce_hashes: Vec<MessageHash>,
    nonce_hash_supplied: Vec<bool>,
}

impl<P, K> NonceHashCollection<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(init: Initialization<P>) -> NonceHashCollection<P> {
        let n = init.joint_key.num_signers;
        let bool_vec = vec![false; n];
        NonceHashCollection {
            joint_key: init.joint_key,
            nonce_hashes: Vec::with_capacity(n),
            nonce_hash_supplied: bool_vec,
        }
    }

    fn all_nonces_supplied(&self) -> bool {
        self.nonce_hash_supplied.iter().all(|v| *v)
    }

    pub fn add_nonce_hash(mut self, pub_key: &P, hash: MessageHash) -> MuSigState<P> {
        match self.joint_key.index_of(pub_key) {
            Ok(i) => {
                self.nonce_hashes.insert(i, hash);
                self.nonce_hash_supplied[i] = true;
                if self.all_nonces_supplied() {
                    MuSigState::NonceCollection
                } else {
                    MuSigState::NonceHashCollection(self)
                }
            },
            Err(e) => MuSigState::Failed(MuSigError::ParticipantNotFound),
        }
    }
}
