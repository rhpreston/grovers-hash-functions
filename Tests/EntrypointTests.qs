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

namespace Quicc {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;


    @Test("QuantumSimulator")
    operation SearchCRC8Test () : Unit {
        let result = SearchCRC8(
            [1, 2, 3, 4],
            12,
            0xBFL
        );

        if (result < 0L) { fail "Failed to reverse CRC-8"; }

        Message("Successfully reversed CRC-8");
        Message($"Result: {result}");
    }

    @Test("QuantumSimulator")
    operation SearchCRC16Test () : Unit {
        let result = SearchCRC16(
            [1, 1], // allow a second try for the small chance of failure
            8,
            0xBF41L
        );

        if (result < 0L) { fail "Failed to reverse CRC-16"; }

        Message("Successfully reversed CRC-16");
        Message($"Result: {result}");
    }

    // The remaining operations are too expensive to fully simulate

}
