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

namespace Quicc.CRC {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    @Test("ToffoliSimulator")
    operation CRC8Test () : Unit {
        let workspace = new Qubit[0];
        using ((input, output) = (Qubit[72], Qubit[8])) {
            let testValue = 0x313233343536373839L; // 123456789
            within {
                LoadLBE(testValue, input);
                CRC8(input, output, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(output),
                    0xF4L,
                    "Invalid checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation CRC16Test () : Unit {
        let workspace = new Qubit[0];
        using ((input, output) = (Qubit[72], Qubit[16])) {
            let testValue = 0x313233343536373839L; // 123456789
            within {
                LoadLBE(testValue, input);
                CRC16(input, output, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(output),
                    0xBB3DL,
                    "Invalid checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation CRC32Test () : Unit {
        let workspace = new Qubit[0];
        using ((input, output) = (Qubit[72], Qubit[32])) {
            let testValue = 0x313233343536373839L; // 123456789
            within {
                LoadLBE(testValue, input);
                CRC32(input, output, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(output),
                    0xCBF43926L,
                    "Invalid checksum"
                );
            }
        }
    }
}
