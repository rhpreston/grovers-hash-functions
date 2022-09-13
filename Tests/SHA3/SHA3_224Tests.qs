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


    operation SHA3_224TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[224],
            Qubit[0]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA3_224(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA3-224 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA3_224EmptyTest () : Unit
    {
        // ""
        SHA3_224TestGeneric(
            0L,
            0,
            0x6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224aTest () : Unit
    {
        // "a"
        SHA3_224TestGeneric(
            0x61L,
            1,
            0x9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8bL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224abcTest () : Unit
    {
        // "abc"
        SHA3_224TestGeneric(
            0x616263L,
            3,
            0xe642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdfL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224MessageTest () : Unit
    {
        // "message digest"
        SHA3_224TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0x18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA3_224TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA3_224TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xa67c289b8250a6f437a20137985d605589a8c163d45261b15419556eL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_224LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA3_224TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8L
        );
    }
}
