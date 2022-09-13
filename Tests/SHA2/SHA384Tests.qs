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

namespace Quicc.SHA2 {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    /// # Summary
    /// Conducts a test on `Quicc.SHA2.SHA384`.
    /// 
    /// # Input
    /// ## testValue
    /// Big integer containing input message data. For example, to test the
    /// string "hi", use the value `0x6869L`.
    /// 
    /// ## messageLength
    /// Integer specifying the length, in bytes, of the input message.
    /// 
    /// ## checksum
    /// Big integer containing the known SHA-384 checksum of the input message.
    operation SHA384TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[384],
            Qubit[SHA384WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA384(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-384 digest does not match checksum"
                );
            }
        }
    }
    
    @Test("ToffoliSimulator")
    operation SHA384EmptyTest () : Unit
    {
        // ""
        SHA384TestGeneric(
            0L,
            0,
            0x38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95bL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384aTest () : Unit
    {
        // "a"
        SHA384TestGeneric(
            0x61L,
            1,
            0x54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384abcTest () : Unit
    {
        // "abc"
        SHA384TestGeneric(
            0x616263L,
            3,
            0xcb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384MessageTest () : Unit
    {
        // "message digest"
        SHA384TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0x473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA384TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xfeb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA384TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0x1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA384LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA384TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0xb12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026L
        );
    }
}
