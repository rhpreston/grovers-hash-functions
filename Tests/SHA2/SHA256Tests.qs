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
    /// Conducts a test on `Quicc.SHA2.SHA256`.
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
    /// Big integer containing the known SHA-256 checksum of the input message.
    operation SHA256TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[256],
            Qubit[SHA256WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA256(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-256 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA256EmptyTest () : Unit
    {
        // ""
        SHA256TestGeneric(
            0L,
            0,
            0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256aTest () : Unit
    {
        // "a"
        SHA256TestGeneric(
            0x61L,
            1,
            0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bbL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256abcTest () : Unit
    {
        // "abc"
        SHA256TestGeneric(
            0x616263L,
            3,
            0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015adL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256MessageTest () : Unit
    {
        // "message digest"
        SHA256TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xf7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA256TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA256TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xdb4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA256LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA256TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0xf371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813eL
        );
    }
}
