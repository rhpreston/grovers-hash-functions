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


    /// # Summary
    /// Number of workspace qubits needed for SHA-512/224.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function SHA512_224WorkspaceRequirement (inputLength : Int) : Int {
        return SHA512WorkspaceRequirement(inputLength) + 288;
    }

    /// # Summary
    /// Runs a quantum implementation of SHA-512/224.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 224-qubit register to store the output.
    /// 
    /// ## workspace
    /// Qubit register required to run the algorithm. Use
    /// `Quicc.SHA2.SHA512_224WorkspaceRequirement` to determine the
    /// appropriate length.
    operation SHA512_224 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let initValues = [
            0x8C3D37C8, 0x19544DA2, 0x73E19966, 0x89DCD4D6,
            0x1DFAB7AE, 0x32FF9C82, 0x679DD514, 0x582F9FCF,
            0x0F6D2B69, 0x7BD44DA8, 0x77E36F73, 0x04C48942,
            0x3F9D85A8, 0x6A1D36C8, 0x1112E6AD, 0x91D692A1
        ];

        SHA2(initValues, input, digest + workspace[0 .. 287],
             workspace[288 ...]);
    }
}
