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


    operation SHAKE128TestGeneric (
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
                SHAKE128(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHAKE128 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHAKE128EmptyTest () : Unit
    {
        // ""
        SHAKE128TestGeneric(
            0L,
            0,
            0x7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128aTest () : Unit
    {
        // "a"
        SHAKE128TestGeneric(
            0x61L,
            1,
            0x85c8de88d28866bf0868090b3961162bf82392f690d9e4730910f4af7c6ab3eeL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128abcTest () : Unit
    {
        // "abc"
        SHAKE128TestGeneric(
            0x616263L,
            3,
            0x5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128MessageTest () : Unit
    {
        // "message digest"
        SHAKE128TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xcbef732961b55b4c31396796577df491b6eed61d8949ce967226801e411e53f0L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHAKE128TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0x961c919c0854576e561320e81514bf3724197d0715e16a364520384ee997f6efL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHAKE128TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0x54dd201e53249910db3c7d366574fbb64e71fae442a4bac13439f26dd4896883L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE128LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHAKE128TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x7bf451c92fdc77b9771e6c9056445894ee867f00c2b70d3af0d196a0cf6b28e1L
        );
    }
}
