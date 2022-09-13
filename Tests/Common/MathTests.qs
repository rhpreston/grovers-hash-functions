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
    operation XorTest () : Unit {
        using ((control, target) = (Qubit[4], Qubit[4])) {
            within {
                LoadI(3, control);
                LoadI(5, target);
                Xor(control, target);
            }
            apply {
                EqualityFactI(
                    MeasureI(target),
                    6,
                    "Xor produced incorrect value"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation NotTest () : Unit {
        using (register = Qubit[2]) {
            within {
                LoadI(2, register);
                Not(register);
            }
            apply {
                EqualityFactI(
                    MeasureI(register),
                    1,
                    "Not produced incorrect value"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation AndTest () : Unit {
        using ((control1, control2, target) = (Qubit[4], Qubit[4], Qubit[4])) {
            within {
                LoadI(3, control1);
                LoadI(5, control2);
                And(control1, control2, target);
            }
            apply {
                EqualityFactI(
                    MeasureI(target),
                    1,
                    "And produced incorrect value"
                );
            }
        }
    }

    operation OrTest () : Unit {
        using ((control1, control2, target) = (Qubit[4], Qubit[4], Qubit[4])) {
            within {
                LoadI(3, control1);
                LoadI(5, control2);
                Or(control1, control2, target);
            }
            apply {
                EqualityFactI(
                    MeasureI(target),
                    7,
                    "Or produced incorrect value"
                );
            }
        }
    }
}
