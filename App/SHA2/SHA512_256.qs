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
    /// Number of workspace qubits needed for SHA-512/256.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function SHA512_256WorkspaceRequirement (inputLength : Int) : Int {
        return SHA512WorkspaceRequirement(inputLength) + 256;
    }

    /// # Summary
    /// Runs a quantum implementation of SHA-512/256.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 256-qubit register to store the output.
    /// 
    /// ## workspace
    /// Qubit register required to run the algorithm. Use
    /// `Quicc.SHA2.SHA512_256WorkspaceRequirement` to determine the
    /// appropriate length.
    operation SHA512_256 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let initValues = [
            0x22312194, 0xFC2BF72C, 0x9F555FA3, 0xC84C64C2,
            0x2393B86B, 0x6F53B151, 0x96387719, 0x5940EABD,
            0x96283EE2, 0xA88EFFE3, 0xBE5E1E25, 0x53863992,
            0x2B0199FC, 0x2C85B8AA, 0x0EB72DDC, 0x81C52CA2
        ];

        SHA2(initValues, input, digest + workspace[0 .. 255],
             workspace[256 ...]);
    }
}
