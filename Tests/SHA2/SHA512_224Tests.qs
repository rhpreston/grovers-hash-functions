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
    /// Conducts a test on `Quicc.SHA2.SHA512_224`.
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
    /// Big integer containing the known SHA-512/224 checksum of the input
    /// message.
    operation SHA512_224TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[224],
            Qubit[SHA512_224WorkspaceRequirement(messageLength*8)]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA512_224(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA-512/224 digest does not match checksum"
                );
            }
        }
    }
    
    @Test("ToffoliSimulator")
    operation SHA512_224EmptyTest () : Unit
    {
        // ""
        SHA512_224TestGeneric(
            0L,
            0,
            0x6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224aTest () : Unit
    {
        // "a"
        SHA512_224TestGeneric(
            0x61L,
            1,
            0xd5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224abcTest () : Unit
    {
        // "abc"
        SHA512_224TestGeneric(
            0x616263L,
            3,
            0x4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aaL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224MessageTest () : Unit
    {
        // "message digest"
        SHA512_224TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA512_224TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA512_224TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xa8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA512_224LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA512_224TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0xae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2L
        );
    }
}
