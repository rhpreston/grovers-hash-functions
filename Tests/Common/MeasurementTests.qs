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
    operation MeasureBoolArrayTest () : Unit {
        using (register = Qubit[2]) {
            X(register[1]);
            AllEqualityFactB(
                MeasureBoolArray(register),
                [false, true],
                "MeasureBoolArray returned incorrect results"
            );
            X(register[1]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureITest () : Unit {
        using (register = Qubit[2]) {
            X(register[1]);
            EqualityFactI(
                MeasureI(register),
                2,
                "MeasureI returned incorrect result"
            );
            X(register[1]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureIBETest () : Unit {
        using (register = Qubit[2]) {
            X(register[1]);
            EqualityFactI(
                MeasureIBE(register),
                1,
                "MeasureIBE returned incorrect result"
            );
            X(register[1]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureLTest () : Unit {
        using (register = Qubit[2]) {
            X(register[1]);
            EqualityFactL(
                MeasureL(register),
                2L,
                "MeasureL returned incorrect result"
            );
            X(register[1]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureLBETest () : Unit {
        using (register = Qubit[2]) {
            X(register[1]);
            EqualityFactL(
                MeasureLBE(register),
                1L,
                "MeasureLBE returned incorrect result"
            );
            X(register[1]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureByteArrayTest () : Unit {
        using (register = Qubit[16]) {
            LoadI(1, register[0 .. 7]);
            LoadI(2, register[8 .. 15]);
            let bytes = MeasureByteArray(register);
            EqualityFactI(
                bytes[0],
                1,
                "MeasureByteArray returned incorrect result"
            );
            EqualityFactI(
                bytes[1],
                2,
                "MeasureByteArray returned incorrect result"
            );
            Adjoint LoadI(1, register[0 .. 7]);
            Adjoint LoadI(2, register[8 .. 15]);
        }
    }

    @Test("ToffoliSimulator")
    operation MeasureByteArrayBETest () : Unit {
        using (register = Qubit[16]) {
            LoadI(1, register[7 .. -1 .. 0]);
            LoadI(2, register[15 .. -1 .. 8]);
            let bytes = MeasureByteArrayBE(register);
            EqualityFactI(
                bytes[0],
                1,
                "MeasureByteArrayBE returned incorrect result"
            );
            EqualityFactI(
                bytes[1],
                2,
                "MeasureByteArrayBE returned incorrect result"
            );
            Adjoint LoadI(1, register[7 .. -1 .. 0]);
            Adjoint LoadI(2, register[15 .. -1 .. 8]);
        }
    }
}
