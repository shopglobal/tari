// Copyright 2018 The Tari Project
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
// Portions of this file were originally copyrighted (c) 2018 The Grin Developers, issued under the Apache License,
// Version 2.0, available at http://www.apache.org/licenses/LICENSE-2.0.

 use std::io::Error; //TODO replace with proper error

use tari_core::pow::ProofOfWork;
use tari_core::transaction::{TransactionInput, TransactionOutput, TransactionKernel, BlindingFactor};

///This struct represents a mining worker that will hash all the transaction to find find the ProofOfWork;
#[derive(Clone, Debug, PartialEq)]
pub struct MiningWorker {
    inputs : Vec<TransactionInput>,
    outputs : Vec<TransactionOutput>,
    kernels : Vec<TransactionKernel>,
    offset : BlindingFactor,
    nonce : u64,
}

impl MiningWorker {
    ///This function creates a new mining worker
    ///It only takes in the information required to do the proof of work
    ///It will return Ok if the parameters was supplied correctly
    pub fn new (inputs : Vec<TransactionInput>, outputs : Vec<TransactionOutput>, kernels : Vec<TransactionKernel>, offset : BlindingFactor, starting_nonce : u64) -> Result<MiningWorker, Error>
    {
        Ok(MiningWorker{
            inputs,
            outputs,
            kernels,
            offset,
            nonce: starting_nonce,
        })
    }

    ///This function will start the worker on its way to find the nonce for the pow
    pub fn start(&self)->Result<ProofOfWork, Error>
    {
        Ok(ProofOfWork{})
    }
}
