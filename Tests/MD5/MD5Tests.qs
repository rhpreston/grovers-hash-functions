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

namespace Quicc.MD5 {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    /// # Summary
    /// Conducts a test on `Quicc.MD5.MD5`.
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
    /// Big integer containing the known MD5 checksum of the input message.
    operation MD5TestGeneric (
        testValue : BigInt, 
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[128],
            Qubit[MD5WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                MD5(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "MD5 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation MD5EmptyTest () : Unit {
        // ""
        MD5TestGeneric(0L, 0, 0xd41d8cd98f00b204e9800998ecf8427eL);
    }

    @Test("ToffoliSimulator")
    operation MD5aTest () : Unit
    {
        // "a"
        MD5TestGeneric(0x61L, 1, 0x0cc175b9c0f1b6a831c399e269772661L);
    }

    @Test("ToffoliSimulator")
    operation MD5abcTest () : Unit
    {
        // "abc"
        MD5TestGeneric(0x616263L, 3, 0x900150983cd24fb0d6963f7d28e17f72L);
    }

    @Test("ToffoliSimulator")
    operation MD5MessageTest () : Unit
    {
        // "message digest"
        MD5TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xf96b697d7cb7938d525a2f31aaf161d0L
        );
    }

    @Test("ToffoliSimulator")
    operation MD5AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        MD5TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xc3fcd3d76192e4007dfb496cca67e13bL
        );
    }

    @Test("ToffoliSimulator")
    operation MD5AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        MD5TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xd174ab98d277d9f5a5611c2c9f419d9fL
        );
    }

    @Test("ToffoliSimulator")
    operation MD5LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        MD5TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x57edf4a22be3c955ac49da2e2107b67aL
        );
    }
}
