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


    operation SHA3_384TestGeneric (
        testValue : BigInt,
        messageLength : Int,
        checksum : BigInt
    ) : Unit {
        using ((input, digest, workspace) = (
            Qubit[messageLength*8],
            Qubit[384],
            Qubit[0]
        )) {
            within {
                LoadLBE(testValue, input);
                SHA3_384(input, digest, workspace);
            }
            apply {
                EqualityFactL(
                    MeasureLBE(digest),
                    checksum,
                    "SHA3-384 digest does not match checksum"
                );
            }
        }
    }

    @Test("ToffoliSimulator")
    operation SHA3_384EmptyTest () : Unit
    {
        // ""
        SHA3_384TestGeneric(
            0L,
            0,
            0x0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384aTest () : Unit
    {
        // "a"
        SHA3_384TestGeneric(
            0x61L,
            1,
            0x1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384abcTest () : Unit
    {
        // "abc"
        SHA3_384TestGeneric(
            0x616263L,
            3,
            0xec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384MessageTest () : Unit
    {
        // "message digest"
        SHA3_384TestGeneric(
            0x6d65737361676520646967657374L,
            14,
            0xd9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384AlphabetTest () : Unit
    {
        // "abcdefghijklmnopqrstuvwxyz"
        SHA3_384TestGeneric(
            0x6162636465666768696a6b6c6d6e6f707172737475767778797aL,
            26,
            0xfed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278fL
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384AlphanumericTest () : Unit
    {
        // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        SHA3_384TestGeneric(
            0x4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839L,
            62,
            0xd5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291L
        );
    }

    @Test("ToffoliSimulator")
    operation SHA3_384LongTest () : Unit
    {
        // "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        SHA3_384TestGeneric(
            0x3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930L,
            80,
            0x3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5eL
        );
    }
}
