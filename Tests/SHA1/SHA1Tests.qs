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

namespace Quicc.SHA1 {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Diagnostics;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    /// # Summary
    /// Conducts a test on `Quicc.SHA1.SHA1`.
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
    /// Big integer containing the known SHA-1 checksum of the input message.
    operation SHA1TestGeneric (
        testValue : BigInt, 
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[160],
            Qubit[SHA1WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA1(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-1 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA1EmptyTest () : Unit
    {
        // ""
        SHA1TestGeneric(0L, 0, 0xda39a3ee5e6b4b0d3255bfef95601890afd80709L);
    }

    @Test("ToffoliSimulator")
    operation SHA1aTest () : Unit
    {
        // "a"
        SHA1TestGeneric(0x61L, 1, 0x86f7e437faa5a7fce15d1ddcb9eaeaea377667b8L);
    }

    @Test("ToffoliSimulator")
    operation SHA1abcTest () : Unit
    {
        // "abc"
        SHA1TestGeneric(
            0x616263L,
            3,
            0xa9993e364706816aba3e25717850c26c9cd0d89dL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA1MessageTest () : Unit
    {
        // "message digest"
        SHA1TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xc12252ceda8be8994d5fa0290a47231c1d16aae3L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA1AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA1TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x32d10c7b8cf96570ca04ce37f2a19d84240d3a89L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA1AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA1TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0x761c457bf73b14d27e9e9265c46f4b4dda11f940L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA1LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA1TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x50abf5706a150990a08b2c5ea40fa0e585554732L
        );
    }
}
