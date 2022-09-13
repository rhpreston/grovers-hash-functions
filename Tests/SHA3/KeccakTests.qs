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

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    operation LoadLanes (
        values : BigInt[][],
        lanes : Qubit[][][]
    ) : Unit is Adj {
        for (x in 0 .. 4) {
            for (y in 0 .. 4) {
                LoadL(values[x][y], lanes[x][y]);
            }
        }
    }

    operation TestLanes (expected : BigInt[][], lanes : Qubit[][][]) : Unit {
        for (x in 0 .. 4) {
            for (y in 0 .. 4) {
                EqualityFactL(
                    expected[x][y],
                    MeasureL(lanes[x][y]),
                    $"Incorrect result at [{x},{y}]"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation ThetaTest () : Unit {
        let values = [
            [1L, 2L, 3L, 4L, 5L],
            [6L, 7L, 8L, 9L, 10L],
            [11L, 12L, 13L, 14L, 15L],
            [16L, 17L, 18L, 19L, 20L],
            [21L, 22L, 23L, 24L, 25L]
        ];
        let expected = [
            [0L, 3L, 2L, 5L, 4L],
            [17L, 16L, 31L, 30L, 29L],
            [41L, 46L, 47L, 44L, 45L],
            [49L, 48L, 51L, 50L, 53L],
            [3L, 0L, 1L, 14L, 15L]
        ];
        using (register = Qubit[1600]) {
            let lanes = ArrayAsWords(5, ArrayAsWords(64, register));
            within {
                LoadLanes(values, lanes);
                Theta(lanes);
            }
            apply {
                TestLanes(expected, lanes);
            }
        }
    }

    @Test("ToffoliSimulator")
    operation RhoPiTest () : Unit {
        let values = [
            [1L, 2L, 3L, 4L, 5L],
            [6L, 7L, 8L, 9L, 10L],
            [11L, 12L, 13L, 14L, 15L],
            [16L, 17L, 18L, 19L, 20L],
            [21L, 22L, 23L, 24L, 25L]
        ];
        let expected = [
            [1L, 4294967296L, 12L, 2818572288L, 13835058055282163714L],
            [123145302310912L, 23068672L, 768L, 137438953472L, 612489549322387456L],
            [114349209288704L, 24L, 603979776L, 8192L, 12644383719424L],
            [39845888L, 316659348799488L, 6144L, 458752L, 8796093022208L],
            [409600L, 16140901064495857665L, 1310720L, 1441151880758558720L, 40L]
        ];
        using (register = Qubit[1600]) {
            let lanes = ArrayAsWords(5, ArrayAsWords(64, register));
            within {
                LoadLanes(values, lanes);
            }
            apply {
                TestLanes(expected, RhoPi(lanes));
            }
        }
    }

    @Test("ToffoliSimulator")
    operation ReverseRhoPiTest () : Unit {
        let values = [
            [1L, 4294967296L, 12L, 2818572288L, 13835058055282163714L],
            [123145302310912L, 23068672L, 768L, 137438953472L, 612489549322387456L],
            [114349209288704L, 24L, 603979776L, 8192L, 12644383719424L],
            [39845888L, 316659348799488L, 6144L, 458752L, 8796093022208L],
            [409600L, 16140901064495857665L, 1310720L, 1441151880758558720L, 40L]
        ];
        let expected = [
            [1L, 2L, 3L, 4L, 5L],
            [6L, 7L, 8L, 9L, 10L],
            [11L, 12L, 13L, 14L, 15L],
            [16L, 17L, 18L, 19L, 20L],
            [21L, 22L, 23L, 24L, 25L]
        ];
        using (register = Qubit[1600]) {
            let lanes = ArrayAsWords(5, ArrayAsWords(64, register));
            within {
                LoadLanes(values, lanes);
            }
            apply {
                TestLanes(expected, ReverseRhoPi(lanes));
            }
        }
    }

    @Test("ToffoliSimulator")
    operation ChiTest () : Unit {
        let values = [
            [1L, 2L, 3L, 4L, 5L],
            [6L, 7L, 8L, 9L, 10L],
            [11L, 12L, 13L, 14L, 15L],
            [16L, 17L, 18L, 19L, 20L],
            [21L, 22L, 23L, 24L, 25L]
        ];
        let expected = [
            [8L, 10L, 6L, 2L, 0L],
            [22L, 22L, 26L, 24L, 26L],
            [14L, 10L, 8L, 6L, 6L],
            [16L, 17L, 18L, 23L, 16L],
            [19L, 19L, 31L, 17L, 19L]
        ];
        using (register = Qubit[1600]) {
            let lanes = ArrayAsWords(5, ArrayAsWords(64, register));
            within {
                LoadLanes(values, lanes);
                Chi(lanes);
            }
            apply {
                TestLanes(expected, lanes);
            }
        }
    }
}
