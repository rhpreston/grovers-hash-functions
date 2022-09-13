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


    operation SHA3_256TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[256],
            Qubit[0]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA3_256(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA3-256 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA3_256EmptyTest () : Unit
    {
        // ""
        SHA3_256TestGeneric(
            0L,
            0,
            0xa7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434aL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256aTest () : Unit
    {
        // "a"
        SHA3_256TestGeneric(
            0x61L,
            1,
            0x80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8bL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256abcTest () : Unit
    {
        // "abc"
        SHA3_256TestGeneric(
            0x616263L,
            3,
            0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256MessageTest () : Unit
    {
        // "message digest"
        SHA3_256TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xedcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffdL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA3_256TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA3_256TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xa79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9fL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_256LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA3_256TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1dL
        );
    }
}
