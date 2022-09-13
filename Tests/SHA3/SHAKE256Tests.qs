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


    operation SHAKE256TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[512],
            Qubit[0]
        )) {
            within {
                LoadLBE(testValue, input);
                SHAKE256(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHAKE256 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHAKE256EmptyTest () : Unit
    {
        // ""
        SHAKE256TestGeneric(
            0L,
            0,
            0x46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4beL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256aTest () : Unit
    {
        // "a"
        SHAKE256TestGeneric(
            0x61L,
            1,
            0x867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba436b7b1ec0e06a279bc790733bb0aee6fa802683c7b355063c434e91189b0c651L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256abcTest () : Unit
    {
        // "abc"
        SHAKE256TestGeneric(
            0x616263L,
            3,
            0x483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4L
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256MessageTest () : Unit
    {
        // "message digest"
        SHAKE256TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0x718e224088856840ade4dc73487e15826a07ecb8ed5e2bda526cc1acddb99d006049815844be0c6c29b759db80b7daa684cb46d90f7eef107d24aafcfaf0dacaL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHAKE256TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xb7b78b04a3dd30a265c8886c33fda94799853de5d3d10541fd4e9f4613701c61075249bed16b0781108fcfe086dbf38a7fb8300807cea85cc649328d07d4ff2bL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHAKE256TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0x31f19a097c723e91fa59b0998dd8523c2a9e7e13b4025d6b48fcbc328973a10878cfbeb3810d882fdb6a06e87f3ea52cf826ca5522316fb645b708acbe43b2cbL
        );
    }

    @Test("ToffoliSimulator")
    operation SHAKE256LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHAKE256TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x24c508adefdf5e3f2596e8b5a888fe10eb7b5b22e1f35d858e6eff3025c4cc18a3c9ace51ddd243d08c8c70cf68e91d170603dc3e2a31c6ca89f20c4a595a265L
        );
    }
}
