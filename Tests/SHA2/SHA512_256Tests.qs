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
    /// Conducts a test on `Quicc.SHA2.SHA512_256`.
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
    /// Big integer containing the known SHA-512/256 checksum of the input
    /// message.
    operation SHA512_256TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[256],
            Qubit[SHA512_256WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA512_256(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-512/256 digest does not match checksum"
                );
            }
        }
    }
    
    @Test("ToffoliSimulator")
    operation SHA512_256EmptyTest () : Unit
    {
        // ""
        SHA512_256TestGeneric(
            0L,
            0,
            0xc672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967aL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256aTest () : Unit
    {
        // "a"
        SHA512_256TestGeneric(
            0x61L,
            1,
            0x455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256abcTest () : Unit
    {
        // "abc"
        SHA512_256TestGeneric(
            0x616263L,
            3,
            0x53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256MessageTest () : Unit
    {
        // "message digest"
        SHA512_256TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0x0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fbL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA512_256TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xfc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA512_256TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xcdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_256LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA512_256TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148L
        );
    }
}
