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

namespace Quicc.Search {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;


    operation TestOp (
        input : Qubit[],
        output : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        Controlled X(input, output[0]);
    }

    operation TestOracle (input : Qubit[], target : Qubit) : Unit is Adj {
        Controlled Z(input, target);
    }

    @Test("ToffoliSimulator")
    function NumIterationsTest () : Unit {
        EqualityFactI(
            NumIterations(4, 1),
            3,
            "Incorrect number of iterations"
        );
        EqualityFactI(
            NumIterations(8, 2),
            8,
            "Incorrect number of iterations"
        );
    }

    @Test("QuantumSimulator")
    operation PerformSearchOnOpTest () : Unit {
        let searchResult = PerformSearchOnOp([1], 8, 8, 0, 0x80L, TestOp);
        EqualityFactL(searchResult, 0xFFL, "Search failed");

        let searchResult2 = PerformSearchOnOp([1, 2], 8, 8, 0, 0xFFL, TestOp);
        EqualityFactL(searchResult2, -1L, "Should return -1L on failure");
    }

    @Test("QuantumSimulator")
    operation OpAsOracleTest () : Unit {
        let oracle = OpAsOracle(8, 0, 0x80L, TestOp, _, _);

        using ((input, target) = (Qubit[1], Qubit())) {
            X(input[0]);
            H(target);

            oracle(input, target);
            H(target);
            EqualityFactR(
                M(target),
                One,
                "Oracle did not flip target correctly"
            );

            X(input[0]);
            X(target);
        }
    }

    @Test("QuantumSimulator")
    operation RunGroverOnOracleTest () : Unit {
        using (input = Qubit[8]) {
            RunGroverOnOracle(12, TestOracle, input);
            for (qubit in input) {
                AssertQubitWithinTolerance(
                    One,
                    qubit,
                    1e-4
                );
            }
            ResetAll(input);
        }
    }

    @Test("QuantumSimulator")
    operation CheckSearchResultTest () : Unit {
        using (input = Qubit[1]) {
            EqualityFactB(
                CheckSearchResult(TestOracle, input),
                false,
                "CheckSearchResult returned incorrect value"
            );

            X(input[0]);
            EqualityFactB(
                CheckSearchResult(TestOracle, input),
                true,
                "CheckSearchResult returned incorrect value"
            );

            X(input[0]);
        }
    }
}
