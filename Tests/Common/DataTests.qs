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

namespace Quicc.Common {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;


    @Test("ToffoliSimulator")
    operation ArrayAsWordsTest () : Unit {
        using (register = Qubit[64]) {
            LoadI(1, register[0 .. 31]);
            LoadI(2, register[32 ...]);
            let words = ArrayAsWords(32, register);
            EqualityFactI(
                MeasureI(words[0]),
                1,
                "Register was not correctly broken into words"
            );
            EqualityFactI(
                MeasureI(words[1]),
                2,
                "Register was not correctly broken into words"
            );
            Adjoint LoadI(1, register[0 .. 31]);
            Adjoint LoadI(2, register[32 ...]);
        }
    }

    @Test("ToffoliSimulator")
    operation ReversedBytesTest () : Unit {
        using (register = Qubit[16]) {
            LoadI(1, register[0 .. 7]);
            LoadI(2, register[8 .. 15]);
            let reversedBytes = ReversedBytes(register);
            EqualityFactI(
                MeasureIBE(reversedBytes[0 .. 7]),
                1,
                "Byte endianness was not correctly reversed"
            );
            EqualityFactI(
                MeasureIBE(reversedBytes[8 .. 15]),
                2,
                "Byte endianness was not correctly reversed"
            );
            Adjoint LoadI(1, register[0 .. 7]);
            Adjoint LoadI(2, register[8 .. 15]);
        }
    }

    @Test("ToffoliSimulator")
    operation LoadBoolArrayTest () : Unit {
        using (register = Qubit[2]) {
            LoadBoolArray([false, true], register);
            AllEqualityFactB(
                MeasureBoolArray(register),
                [false, true],
                "LoadBoolArray loaded register incorrectly"
            );
            Adjoint LoadBoolArray([false, true], register);
        }
    }

    @Test("ToffoliSimulator")
    operation LoadITest () : Unit {
        using (register = Qubit[2]) {
            LoadI(2, register);
            EqualityFactI(
                MeasureI(register),
                2,
                "LoadI loaded register incorrectly"
            );
            Adjoint LoadI(2, register);
        }
    }

    @Test("ToffoliSimulator")
    operation LoadIBETest () : Unit {
        using (register = Qubit[2]) {
            LoadIBE(2, register);
            EqualityFactI(
                MeasureIBE(register),
                2,
                "LoadI loaded register incorrectly"
            );
            Adjoint LoadIBE(2, register);
        }
    }

    @Test("ToffoliSimulator")
    operation LoadLTest () : Unit {
        using (register = Qubit[2]) {
            LoadL(2L, register);
            EqualityFactL(
                MeasureL(register),
                2L,
                "LoadL loaded register incorrectly"
            );
            Adjoint LoadL(2L, register);
        }
    }

    @Test("ToffoliSimulator")
    operation LoadLBETest () : Unit {
        using (register = Qubit[2]) {
            LoadLBE(2L, register);
            EqualityFactL(
                MeasureLBE(register),
                2L,
                "LoadL loaded register incorrectly"
            );
            Adjoint LoadLBE(2L, register);
        }
    }
}
