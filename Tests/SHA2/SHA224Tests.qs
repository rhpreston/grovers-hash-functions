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
    /// Conducts a test on `Quicc.SHA2.SHA224`.
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
    /// Big integer containing the known SHA-224 checksum of the input message.
    operation SHA224TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[224],
            Qubit[SHA224WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA224(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-224 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA224EmptyTest () : Unit
    {
        // ""
        SHA224TestGeneric(
            0L,
            0,
            0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42fL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224aTest () : Unit
    {
        // "a"
        SHA224TestGeneric(
            0x61L,
            1,
            0xabd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224abcTest () : Unit
    {
        // "abc"
        SHA224TestGeneric(
            0x616263L,
            3,
            0x23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224MessageTest () : Unit
    {
        // "message digest"
        SHA224TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0x2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8ebL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA224TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA224TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xbff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA224LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA224TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0xb50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046eL
        );
    }
}
