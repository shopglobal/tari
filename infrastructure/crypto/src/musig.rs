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
use std::ops::Add;

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
    // There are too few parties in the MuSig signature
    NotEnoughParticipants,
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
pub struct JointKey<P, K>
    where
        K: SecretKey,
        P: PublicKey<K=K>,
{
    pub_keys: Vec<P>,
    musig_scalars: Vec<K>,
    common: K,
    joint_pub_key: P,
}

pub struct JointKeyBuilder<P, K>
    where
        K: SecretKey,
        P: PublicKey<K=K>,
{
    num_signers: usize,
    pub_keys: Vec<P>,
}


impl<K, P> JointKeyBuilder<P, K>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    /// Create a new JointKey instance containing no participant keys, or return `TooManyParticipants` if n exceeds
    /// `MAX_SIGNATURES`
    pub fn new(n: usize) -> Result<JointKeyBuilder<P, K>, MuSigError> {
        if n > MAX_SIGNATURES {
            return Err(MuSigError::TooManyParticipants);
        }
        Ok(JointKeyBuilder {
            pub_keys: Vec::with_capacity(n),
            num_signers: n,
        })
    }

    /// The number of parties in the Joint key
    pub fn num_signers(&self) -> usize {
        self.num_signers
    }

    /// Add a participant signer's public key to the JointKey
    pub fn add_key(&mut self, pub_key: P) -> Result<usize, MuSigError> {
        if self.key_exists(&pub_key) {
            return Err(MuSigError::DuplicatePubKey);
        }
        // push panics on int overflow, so catch this here
        let n = self.pub_keys.len();
        if n >= MAX_SIGNATURES {
            return Err(MuSigError::TooManyParticipants);
        }
        self.pub_keys.push(pub_key);
        Ok(self.pub_keys.len())
    }

    /// Checks whether the given public key is in the participants list
    pub fn key_exists(&self, key: &P) -> bool {
        self.pub_keys.iter().find(|v| *v == key).is_none()
    }

    /// Checks whether the number of pub_keys is equal to `num_signers`
    pub fn is_full(&self) -> bool {
        self.pub_keys.len() == self.num_signers
    }

    /// Add all the keys in `keys` to the participant list.
    pub fn add_keys<T: IntoIterator<Item=P>>(&mut self, keys: T) -> Result<usize, MuSigError> {
        for k in keys.into_iter() {
            self.add_key(k)?;
        }
        Ok(self.pub_keys.len())
    }

    /// Produce a sorted, immutable joint Musig public key from the gathered set of conventional public keys
    pub fn build<D: Digest>(mut self) -> Result<JointKey<P, K>, MuSigError> {
        if !self.is_full() {
            return Err(MuSigError::NotEnoughParticipants);
        }
        self.sort_keys();
        let common = self.calculate_common::<D>();
        let musig_scalars = self.calculate_musig_scalars::<D>(&common);
        let joint_pub_key = JointKeyBuilder::calculate_joint_key::<D>(&musig_scalars, &self.pub_keys);
        Ok(JointKey { pub_keys: self.pub_keys, musig_scalars, joint_pub_key, common })
    }

    /// Utility function to calculate \\( \ell = H(P_1 || ... || P_n) \mod p \\)
    /// # Panics
    /// If the SecretKey implementation cannot construct a valid key from the given hash, the function will panic.
    /// You should ensure that the SecretKey constructor protects against failures and that the hash digest given
    /// produces a byte array of the correct length.
    fn calculate_common<D: Digest>(&self) -> K {
        let mut common = Challenge::<D>::new();
        for k in self.pub_keys.iter() {
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
    fn sort_keys(&mut self) {
        self.pub_keys.sort_unstable();
    }

    /// Utility function that produces the vector of MuSig private key modifiers, \\( a_i = H(\ell || P_i) \\)
    fn calculate_musig_scalars<D: Digest>(&self, common: &K) -> Vec<K> {
        self.pub_keys
            .iter()
            .map(|p| JointKeyBuilder::calculate_partial_key::<D>(common.to_bytes(), p))
            .collect()
    }

    /// Calculate the value of the Joint MuSig public key. **NB**: you should usually sort the participant's keys
    /// before calculating the joint key.
    fn calculate_joint_key<D: Digest>(scalars: &Vec<K>, pub_keys: &Vec<P>) -> P {
        P::batch_mul(scalars, pub_keys)
    }
}

impl<P, K> JointKey<P, K>
    where
        K: SecretKey,
        P: PublicKey<K=K>,
{
    /// Return the index of the given key in the joint key participants list. If the list isn't sorted, returns
    /// Err(`NotSorted`), and if the key isn't in the list, returns `Err(ParticipantNotFound)`
    pub fn index_of(&self, pubkey: &P) -> Result<usize, MuSigError> {
        match self.pub_keys.binary_search(pubkey) {
            Ok(i) => Ok(i),
            Err(_) => Err(MuSigError::ParticipantNotFound),
        }
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.pub_keys.len()
    }

    #[inline]
    pub fn get_pub_keys(&self, index: usize) -> &P {
        &self.pub_keys[index]
    }

    #[inline]
    pub fn get_musig_scalar(&self, index: usize) -> &K {
        &self.musig_scalars[index]
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
pub struct MuSig<P, K>
    where
        K: SecretKey,
        P: PublicKey<K=K>,
{
    state: MuSigState<P, K>,
}

impl<K, P> MuSig<P, K>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    /// Create a new, empty MuSig ceremony for _n_ participants
    pub fn new(n: usize) -> MuSig<P, K> {
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

    pub fn add_public_key<D: Digest>(self, key: &P) -> Self {
        let key = key.clone();
        self.handle_event::<D>(MuSigEvent::AddKey(key))
    }

    pub fn add_nonce_commitment<D: Digest>(self, pub_key: &P, commitment: MessageHash) -> Self {
        self.handle_event::<D>(MuSigEvent::AddNonceHash(pub_key, commitment))
    }

    /// Private convenience function that returns a Failed state with the `InvalidStateTransition` error
    fn invalid_transition() -> MuSigState<P, K> {
        MuSigState::Failed(MuSigError::InvalidStateTransition)
    }

    /// Implement a finite state machine. Each combination of State and Event is handled here; for each combination, a
    /// new state is determined, consuming the old one. If `MuSigState::Failed` is ever returned, the protocol must be
    /// abandoned.
    fn handle_event<D: Digest>(self, event: MuSigEvent<P>) -> Self {
        let state = match self.state {
            // On initialization, you can add keys until you reach `num_signers` at which point the state
            // automatically flips to `NonceHashCollection`; we're forced to use nested patterns because of error
            MuSigState::Initialization(s) => {
                match event {
                    MuSigEvent::AddKey(p) => s.add_pubkey::<D>(p),
                    _ => MuSig::invalid_transition(),
                }
            }
            // Nonce Hash collection
            MuSigState::NonceHashCollection(s) => {
                match event {
                    MuSigEvent::AddNonceHash(p, h) => s.add_nonce_hash::<D>(p, h.clone()),
                    _ => MuSig::invalid_transition(),
                }
            }
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
enum MuSigState<P, K>
    where P: PublicKey<K=K>, K: SecretKey
{
    Initialization(Initialization<P, K>),
    NonceHashCollection(NonceHashCollection<P, K>),
    NonceCollection(NonceCollection<P, K>),
    SignatureCollection(SignatureCollection<P, K>),
    Finalized(SchnorrSignature<P, K>),
    Failed(MuSigError),
}

struct Initialization<P, K>
    where P: PublicKey<K=K>, K: SecretKey, {
    joint_key_builder: JointKeyBuilder<P, K>,
}

impl<P, K> Initialization<P, K>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    pub fn new(n: usize) -> Result<Initialization<P, K>, MuSigError> {
        let joint_key_builder = JointKeyBuilder::new(n)?;
        Ok(Initialization { joint_key_builder })
    }

    pub fn add_pubkey<D:Digest>(mut self, key: P) -> MuSigState<P, K> {
        match self.joint_key_builder.add_key(key) {
            Ok(_) => {
                if self.joint_key_builder.is_full() {
                    match self.joint_key_builder.build::<D>() {
                        Ok(jk) => MuSigState::NonceHashCollection(NonceHashCollection::new(jk)),
                        Err(e) => MuSigState::Failed(e),
                    }
                } else {
                    MuSigState::Initialization(self)
                }
            }
            Err(e) => MuSigState::Failed(e),
        }
    }
}

struct NonceHashCollection<P, K> where
    K: SecretKey,
    P: PublicKey<K=K>,
{
    joint_key: JointKey<P, K>,
    nonce_hashes: FixedSet<MessageHash>,
}

impl<P, K> NonceHashCollection<P, K>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(joint_key: JointKey<P, K>) -> NonceHashCollection<P, K> {
        NonceHashCollection {
            joint_key,
            nonce_hashes: FixedSet::new(joint_key.size()),
        }
    }

    fn add_nonce_hash<D:Digest>(mut self, pub_key: &P, hash: MessageHash) -> MuSigState<P, K> {
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

struct NonceCollection<P, K> where
    K: SecretKey,
    P: PublicKey<K=K>,
{
    joint_key: JointKey<P, K>,
    nonce_hashes: FixedSet<MessageHash>,
    public_nonces: FixedSet<P>,
}

impl<P, K> NonceCollection<P, K>
    where
        K: SecretKey + Mul<P, Output=P>,
        P: PublicKey<K=K>,
{
    fn new(init: NonceHashCollection<P, K>) -> NonceCollection<P, K> {
        let n = init.joint_key.size();
        NonceCollection {
            joint_key: init.joint_key,
            nonce_hashes: init.nonce_hashes,
            public_nonces: FixedSet::new(n),
        }
    }

    fn all_nonces_valid<D:Digest>(&self) -> bool {
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
    fn add_nonce<D: Digest>(mut self, pub_key: &P, nonce: P) -> MuSigState<P, K> {
        match self.joint_key.index_of(pub_key) {
            Ok(i) => {
                self.public_nonces.set_item(i, nonce);
                if self.public_nonces.is_full() {
                    MuSigState::SignatureCollection(SignatureCollection::new::<D>(self))
                } else {
                    MuSigState::NonceCollection(self)
                }
            }
            Err(_) => MuSigState::Failed(MuSigError::ParticipantNotFound),
        }
    }
}

struct SignatureCollection<P, K>
    where P: PublicKey<K=K>,
          K: SecretKey,
{
    joint_key: JointKey<P, K>,
    public_nonces: FixedSet<P>,
    partial_signatures: FixedSet<SchnorrSignature<P, K>>,
}

impl<P, K> SignatureCollection<P, K>
    where
        K: SecretKey + PartialEq + Add<Output = K>,
        P: PublicKey<K=K> + Add<Output = P>,
{
    fn new<D: Digest>(init: NonceCollection<P, K>) -> SignatureCollection<P, K> {
        let n = init.joint_key.size();
        SignatureCollection {
            joint_key: init.joint_key,
            public_nonces: init.public_nonces,
            partial_signatures: FixedSet::new(n),
        }
    }

    fn validate_partial_signature<'a, 'b, D: Digest>(&'b self, index: usize, signature: &SchnorrSignature<P, K>) ->
                                                                                                                  bool
    where
     K: 'b + Mul<&'b P, Output=P>,
     P: 'a,
     &'b K: Add<&'b K, Output = K>,
    {
        // s_i = r_i + a_i k_i e, so
        // s_i.G = R_i + a_i P_i e
        let pub_key = self.joint_key.get_pub_keys(index);
        let a_i = self.joint_key.get_musig_scalar(index).clone();
        let e = Challenge::<D>::new();
        let p = a_i * pub_key;
        signature.verify(&p, e)
    }

    fn calculate_agg_signature(self) -> SchnorrSignature<P, K> {
        let s = self.partial_signatures.items;
        let sig = &s[0].unwrap() + &s[0].unwrap();
        //let sig = s.iter().skip(1).fold(s[0].unwrap(), |sum, s| &s.unwrap() + &sum);
        sig
    }

    fn validate_and_set_signature<D:Digest>(mut self, index: usize, signature: SchnorrSignature<P, K>) -> MuSigState<P, K> {
        if self.partial_signatures.set_item(index, signature) {
            if self.partial_signatures.is_full() {
                let s = self.calculate_agg_signature();
                MuSigState::Finalized(s)
            } else {
                MuSigState::SignatureCollection(self)
            }
        } else {
            MuSigState::Failed(MuSigError::MismatchedSignatures)
        }
    }

    fn add_partial_signature<D:Digest>(mut self, signature: SchnorrSignature<P, K>) -> MuSigState<P, K> {
        match self.public_nonces.slow_search(signature.get_public_nonce()) {
            None => MuSigState::Failed(MuSigError::ParticipantNotFound),
            Some(i) => self.validate_and_set_signature::<D>(i, signature)
        }
    }
}

//-------------------------------------------         Fixed Set          ---------------------------------------------//

pub struct FixedSet<T> {
    is_sorted: bool,
    items: Vec<Option<T>>,
}

impl<T: Clone + PartialEq> FixedSet<T> {
    /// Creates a new fixed set of size n.
    pub fn new(n: usize) -> FixedSet<T> {
        FixedSet {
            is_sorted: false,
            items: vec![None; n],
        }
    }

    /// Returns the size of the fixed set, NOT the number of items that have been set
    pub fn size(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the set elements are sorted according to `Ord<P>`.
    pub fn is_sorted(&self) -> bool {
        self.is_sorted
    }

    /// Set the `index`th item to `val`. Any existing item is overwritten. The set takes ownership of `val`.
    pub fn set_item(&mut self, index: usize, val: T) -> bool {
        if index >= self.items.len() {
            return false;
        }
        self.items[index] = Some(val);
        self.is_sorted = false;
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

    /// Return the index of the given item in the set by performing a linear search through the set
    pub fn slow_search(&self, val: &T) -> Option<usize> {
        match self.items.iter()
            .enumerate()
            .find(|v| v.1.is_some() && v.1.unwrap() == *val) {
            Some(item) => Some(item.0),
            None => None,
        }
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
        // Size is 3
        assert_eq!(s.size(), 3);
    }
}