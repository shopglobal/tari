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
            return Err(MuSigError::TooManyParticipants);
        }
        Ok(JointKey {
            is_sorted: false,
            participants: Vec::with_capacity(n),
            num_signers: n,
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
    /// Create a new, empty MuSig ceremony for _n_ participants
    pub fn new(n: usize) -> MuSig<P> {
        let state = match Initialization::new(n) {
            Ok(s) => MuSigState::Initialization(s),
            Err(e) => MuSigState::Failed(e),
        };
        MuSig { state }
    }

    /// Convenience wrapper function to determined whether a signing ceremony has failed
    pub fn has_failed(&self) -> bool {
        match self.state {
            MuSigState::Failed(_) => true,
            _ => false,
        }
    }

    pub fn add_public_key(self, key: &P) -> Self {
        let key = key.clone();
        self.handle_event(MuSigEvent::AddKey(key))
    }

    pub fn add_nonce_commitment(self, pub_key: &P, commitment: MessageHash) -> Self {
        self.handle_event(MuSigEvent::AddNonceHash(pub_key, commitment))
    }

    /// Private convenience function that returns a Failed state with the `InvalidStateTransition` error
    fn invalid_transition() -> MuSigState<P> {
        MuSigState::Failed(MuSigError::InvalidStateTransition)
    }

    /// Implement a finite state machine. Each combination of State and Event is handled here; for each combination, a
    /// new state is determined, consuming the old one. If `MuSigState::Failed` is ever returned, the protocol must be
    /// abandoned.
    fn handle_event(self, event: MuSigEvent<P>) -> Self {
        let state = match self.state {
            // On initialization, you can add keys until you reach `num_signers` at which point the state
            // automatically flips to `NonceHashCollection`; we're forced to use nested patterns because of error
            MuSigState::Initialization(s) => {
                match event {
                    MuSigEvent::AddKey(p) => s.add_pubkey(p),
                    _ => MuSig::invalid_transition(),
                }
            },
            // Nonce Hash collection
            MuSigState::NonceHashCollection(s) => {
                match event {
                    MuSigEvent::AddNonceHash(p, h) => s.add_nonce_hash(p, h.clone()),
                    _ => MuSig::invalid_transition(),
                }
            },
            // There's no way back from a Failed State.
            MuSigState::Failed(_) => MuSig::invalid_transition(),
            _ => MuSig::invalid_transition(),
        };
        MuSig { state }
    }
}

//-------------------------------------------  MuSig Event Definitions ---------------------------------------------//

/// The set of possible input events that can occur during the MuSig signature aggregation protocol.
pub enum MuSigEvent<'a, P: PublicKey> {
    /// This event is used to add a new public key to the pool of participant keys
    AddKey(P),
    /// This event is used by participants to commit the the public nonce that they will be using the signature
    /// aggregation ceremony
    AddNonceHash(&'a P, MessageHash),
    /// This event is used to add a public nonce to the pool of nonces for a particular signing ceremony
    AddNonce,
    /// In the 3rd round of MuSig, participants provide their partial signatures, after which any party can
    /// calculate the aggregated signature.
    AddPartialSig,
}

//-------------------------------------------  MuSig State Definitions ---------------------------------------------//


/// This (private) enum represents the set of states that define the MuSig protocol. Metadata relevant to a given
/// state is supplied as an associated struct of the same name as the struct. Illegal state transitions are prevented
/// by a) there being no way to move from a given state's methods to another state using an invalid transition and b)
/// the global `match` clause in the [MuSig](structs.MuSig.html) struct implementation. Any invalid transition
/// attempt leads to the `Failed` state.
enum MuSigState<P: PublicKey> {
    Initialization(Initialization<P>),
    NonceHashCollection(NonceHashCollection<P>),
    NonceCollection(NonceCollection<P>),
    SignatureCollection(SignatureCollection<P>),
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
    nonce_hashes: FixedSet<MessageHash>,
}

impl<P, K> NonceHashCollection<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(init: Initialization<P>) -> NonceHashCollection<P> {
        let n = init.joint_key.num_signers;
        NonceHashCollection {
            joint_key: init.joint_key,
            nonce_hashes: FixedSet::new(n),
        }
    }

    fn add_nonce_hash(mut self, pub_key: &P, hash: MessageHash) -> MuSigState<P> {
        match self.joint_key.index_of(pub_key) {
            Ok(i) => {
                self.nonce_hashes.set_item(i, hash);
                if self.nonce_hashes.is_full() {
                    MuSigState::NonceCollection(NonceCollection::new(self))
                } else {
                    MuSigState::NonceHashCollection(self)
                }
            }
            Err(_) => MuSigState::Failed(MuSigError::ParticipantNotFound),
        }
    }
}

struct NonceCollection<P: PublicKey> {
    joint_key: JointKey<P>,
    nonce_hashes: FixedSet<MessageHash>,
    public_nonces: FixedSet<P>,
}

impl<P, K> NonceCollection<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(init: NonceHashCollection<P>) -> NonceCollection<P> {
        let n = init.joint_key.num_signers;
        NonceCollection {
            joint_key: init.joint_key,
            nonce_hashes: init.nonce_hashes,
            public_nonces: FixedSet::new(n),
        }
    }

    fn all_nonces_valid<D: Digest>(&self) -> bool {
        if !self.public_nonces.is_full() {
            return false;
        }
        // nonce_hashes must be full, otherwise we wouldn't have gotten to this state. So panic if this is not
        // the case
        self.public_nonces.items.iter()
            .map(|r| Challenge::<D>::hash_input(r.clone().unwrap().to_vec()))
            .zip(self.nonce_hashes.items.iter())
            .all(|(calc, expect)| {
                let expect = expect.as_ref().unwrap();
                calc == *expect
            })
    }

    // We definitely want to consume `nonce` here to discourage nonce re-use
    fn add_nonce(mut self, pub_key: &P, nonce: P) -> MuSigState<P> {
        match self.joint_key.index_of(pub_key) {
            Ok(i) => {
                self.public_nonces.set_item(i, nonce);
                if self.public_nonces.is_full() {
                    MuSigState::SignatureCollection(SignatureCollection::new(self))
                } else {
                    MuSigState::NonceCollection(self)
                }
            }
            Err(_) => MuSigState::Failed(MuSigError::ParticipantNotFound),
        }
    }
}

struct SignatureCollection<P: PublicKey> {
    joint_key: JointKey<P>,
    public_nonces: FixedSet<P>,
    partial_signatures: FixedSet<P>,
}

impl<P, K> SignatureCollection<P>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(init: NonceCollection<P>) -> SignatureCollection<P> {
        let n = init.joint_key.num_signers;
        SignatureCollection {
            joint_key: init.joint_key,
            public_nonces: init.public_nonces,
            partial_signatures: FixedSet::new(n)
        }
    }

    fn add_partial_signature(mut self, signature: &SchnorrSignature) -> MuSigState<P> {

    }
}


//-------------------------------------------         Fixed Set          ---------------------------------------------//

pub struct FixedSet<T> {
    items: Vec<Option<T>>,
}

impl<T: Clone> FixedSet<T> {

    /// Creates a new fixed set of size n.
    pub fn new(n: usize) -> FixedSet<T> {
        FixedSet {
            items: vec![None; n],
        }
    }

    /// Set the `index`th item to `val`. Any existing item is overwritten. The set takes ownership of `val`.
    pub fn set_item(&mut self, index: usize, val: T) -> bool {
        if index >= self.items.len() {
            return false;
        }
        self.items[index] = Some(val);
        true
    }

    /// Return a reference to the `index`th item, or `None` if that item has not been set yet.
    pub fn get_item(&self, index: usize) -> Option<&T> {
        match self.items.get(index) {
            None => None,
            Some(option) => option.as_ref()
        }
    }

    /// Delete an item from the set by setting the `index`th value to None
    pub fn clear_item(&mut self, index: usize) {
        if index < self.items.len() {
            self.items[index] = None;
        }
    }

    /// Returns true if every item in the set has been set. An empty set returns true as well.
    pub fn is_full(&self) -> bool {
        self.items.iter().all(|v| v.is_some())
    }
}

//-------------------------------------------         Tests              ---------------------------------------------//

#[cfg(test)]
mod test {
    use super::FixedSet;

    #[derive(Eq, PartialEq, Clone)]
    struct Foo {
        baz: String,
    }

    #[test]
    fn zero_sized_fixed_set() {
        let mut s = FixedSet::<usize>::new(0);
        assert!(s.is_full(), "Set should be full");
        assert_eq!(s.set_item(1, 1), false, "Should not be able to set item");
        assert_eq!(s.get_item(0), None, "Should not return a value");
    }

    fn data(s: &str) -> Foo {
        match s {
            "patrician" => Foo { baz: "The Patrician".into() },
            "rincewind" => Foo { baz: "Rincewind".into() },
            "vimes" => Foo { baz: "Commander Vimes".into() },
            "librarian" => Foo { baz: "The Librarian".into() },
            "carrot" => Foo { baz: "Captain Carrot".into() },
            _ => Foo { baz: "None".into() },
        }
    }

    #[test]
    fn small_set() {
        let mut s = FixedSet::<Foo>::new(3);
        // Set is empty
        assert_eq!(s.is_full(), false);
        // Add an item
        assert!(s.set_item(1, data("patrician")));
        assert_eq!(s.is_full(), false);
        // Add an item
        assert!(s.set_item(0, data("vimes")));
        assert_eq!(s.is_full(), false);
        // Replace an item
        assert!(s.set_item(1, data("rincewind")));
        assert_eq!(s.is_full(), false);
        // Add item, filling set
        assert!(s.set_item(2, data("carrot")));
        assert_eq!(s.is_full(), true);
        // Try add an invalid item
        assert_eq!(s.set_item(3, data("librarian")), false);
        assert_eq!(s.is_full(), true);
        // Clear an item
        s.clear_item(1);
        assert_eq!(s.is_full(), false);
        // Check contents
        assert_eq!(s.get_item(0).unwrap().baz, "Commander Vimes");
        assert!(s.get_item(1).is_none());
        assert_eq!(s.get_item(2).unwrap().baz, "Captain Carrot");
    }
}