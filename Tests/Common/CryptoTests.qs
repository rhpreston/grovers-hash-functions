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
    function WorkspaceRequirementTest () : Unit {
        EqualityFactI(
            WorkspaceRequirement(128, 512, 64, 447),
            128,
            "Incorrect workspace requirement"
        );
        EqualityFactI(
            WorkspaceRequirement(128, 512, 64, 448),
            256,
            "Incorrect workspace requirement"
        );
    }

    @Test("ToffoliSimulator")
    function MessagePadLengthTest () : Unit {
        EqualityFactI(
            MessagePadLength(447, 512, 64),
            65,
            "Incorrect number of pad qubits"
        );
        EqualityFactI(
            MessagePadLength(448, 512, 64),
            576,
            "Incorrect number of pad qubits"
        );
    }

    @Test("ToffoliSimulator")
    operation PadMessageTest () : Unit {
        using (appendix = Qubit[99]) {
            PadMessage(413, 64, appendix);
            EqualityFactI(
                MeasureI(appendix[3 .. 10]),
                0x80,
                "First aligned byte of appendix should be 0x80"
            );
            EqualityFactL(
                MeasureL(appendix[35 ...]),
                413L,
                "Input length not properly encoded"
            );
            Adjoint PadMessage(413, 64, appendix);
        }
    }

    @Test("ToffoliSimulator")
    operation PadMessageBETest () : Unit {
        using (appendix = Qubit[99]) {
            PadMessageBE(413, 64, appendix);
            EqualityFactI(
                MeasureI(appendix[10 .. -1 .. 3]),
                0x80,
                "First aligned byte of appendix should be 0x80"
            );
            EqualityFactL(
                MeasureL(appendix[98 .. -1 .. 35]),
                413L,
                "Input length not properly encoded"
            );
            Adjoint PadMessageBE(413, 64, appendix);
        }
    }

    @Test("ToffoliSimulator")
    operation LeftRotateTest () : Unit {
        using (register = Qubit[3]) {
            X(register[0]);
            let rotated = LeftRotate(register, 1);
            AllEqualityFactB(
                MeasureBoolArray(rotated),
                [false, false, true],
                "LeftRotate operation rotated qubit register incorrectly"
            );
            X(register[0]);
        }
    }

    @Test("ToffoliSimulator")
    operation RightRotateTest () : Unit {
        using (register = Qubit[3]) {
            X(register[0]);
            let rotated = RightRotate(register, 1);
            AllEqualityFactB(
                MeasureBoolArray(rotated),
                [false, true, false],
                "RightRotate operation rotated qubit register incorrectly"
            );
            X(register[0]);
        }
    }

    @Test("ToffoliSimulator")
    operation ChoiceTest () : Unit {
        using ((control, choice1, choice2) = (Qubit[8], Qubit[8], Qubit[8])) {
            within {
                LoadI(0x0F, control);
                LoadI(0x33, choice1);
                LoadI(0x55, choice2);
                Choice(control, choice1, choice2);
            }
            apply {
                EqualityFactI(
                    MeasureI(choice2),
                    0x53,
                    "Bitwise choice operation truth table is incorrect"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation MajorityTest () : Unit {
        using ((input1, input2, input3) = (Qubit[8], Qubit[8], Qubit[8])) {
            within {
                LoadI(0x0F, input1);
                LoadI(0x33, input2);
                LoadI(0x55, input3);
                Majority(input1, input2, input3);
            }
            apply {
                EqualityFactI(
                    MeasureI(input3),
                    0x17,
                    "Majority operation truth table is incorrect"
                );
            }
        }
    }
}
