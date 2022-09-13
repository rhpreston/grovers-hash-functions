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

namespace Quicc.SHA2 {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    /// # Summary
    /// Number of workspace qubits needed for SHA-512.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function SHA512WorkspaceRequirement (inputLength : Int) : Int {
        return WorkspaceRequirement(512, 1025, 128, inputLength);
    }

    /// # Summary
    /// Runs a quantum implementation of SHA-512.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 512-qubit register to store the output.
    /// 
    /// ## workspace
    /// Qubit register required to run the algorithm. Use
    /// `Quicc.SHA2.SHA512WorkspaceRequirement` to determine the appropriate
    /// length.
    operation SHA512 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let initValues = [
            0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
            0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
            0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
            0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
        ];

        SHA2(initValues, input, digest, workspace);
    }
}
