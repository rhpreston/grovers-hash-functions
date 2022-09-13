﻿// ==========================================================================
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
    /// Number of workspace qubits needed for SHA-224.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function SHA384WorkspaceRequirement (inputLength : Int) : Int {
        return SHA512WorkspaceRequirement(inputLength) + 128;
    }

    /// # Summary
    /// Runs a quantum implementation of SHA-384.
    /// 
    /// # Input
    /// ## input
    /// Input message in big-endian format.
    /// 
    /// ## digest
    /// 384-qubit register to store the output.
    /// 
    /// ## workspace
    /// Qubit register required to run the algorithm. Use
    /// `Quicc.SHA2.SHA384WorkspaceRequirement` to determine the appropriate
    /// length.
    operation SHA384 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let initValues = [
            0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507,
            0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
            0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511,
            0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4
        ];

        SHA2(initValues, input, digest + workspace[0 .. 127],
             workspace[128 ...]);
    }
}
