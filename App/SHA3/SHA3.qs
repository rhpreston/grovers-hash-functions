// ==========================================================================
// Copyright 2022 The MITRE Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// =========================================================================

namespace Quicc.SHA3 {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;


    /// # Summary
    /// Runs a quantum implementation of SHAKE128.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// Qubit register (of any length) to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHAKE128 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(1344, 0x1F, input, digest);
    }

    /// # Summary
    /// Runs a quantum implementation of SHAKE256.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// Qubit register (of any length) to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHAKE256 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(1088, 0x1F, input, digest);
    }

    /// # Summary
    /// Runs a quantum implementation of SHA3-224.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 224-qubit register to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHA3_224 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(1152, 0x06, input, digest);
    }

    /// # Summary
    /// Runs a quantum implementation of SHA3-256.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 224-qubit register to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHA3_256 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(1088, 0x06, input, digest);
    }

    /// # Summary
    /// Runs a quantum implementation of SHA3-384.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 224-qubit register to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHA3_384 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(832, 0x06, input, digest);
    }

    /// # Summary
    /// Runs a quantum implementation of SHA3-512.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 224-qubit register to store the output.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation SHA3_512 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Keccak(576, 0x06, input, digest);
    }
}
