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

namespace Quicc.CRC {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    /// # Summary
    /// Computes the cyclic redundancy check (CRC) of a qubit register.
    /// Logically identical to a classical implementation, except that the
    /// REFIN, REFOUT, and XOROUT parameters are handled outside the operation.
    /// It is not recommended to invoke this operation directly. Instead, use
    /// convenience operations such as Quicc.CRC.CRC8.
    /// 
    /// # Input
    /// ## width
    /// Width of CRC algorithm in bits. This is bit-length of the polynomial
    /// minus 1.
    /// 
    /// ## poly
    /// CRC polynomial expressed as an integer with MSB omitted.
    /// 
    /// ## init
    /// Value to XOR with the first `width` qubits of the input message.
    /// 
    /// ## input
    /// Qubit register containing the input message in big-endian format.
    /// 
    /// ## output
    /// Qubit register to contain output checksum after the operation.
    /// 
    /// # Remarks
    /// This is a toy example. CRC is not meant for cryptography and is easily
    /// reversible on a classical computer. Note also that this operation is
    /// performed more efficiently on a classical computer using a precomputed
    /// table.
    /// 
    /// # References
    /// - Wikipedia:
    ///     https://en.wikipedia.org/wiki/Cyclic_redundancy_check
    /// - A Painless Guide to CRC Error Detection Algorithms:
    ///     https://zlib.net/crc_v3.txt
    /// - Online CRC Calculator:
    ///     https://crccalc.com/
    operation CRC (
        width : Int,
        poly : Int,
        init : Int,
        input : Qubit[],
        output : Qubit[]
    ) : Unit is Adj {
        let augmentedMessage = input + output;

        if (init > 0) {
            LoadIBE(init, augmentedMessage[0 .. width - 1]);
        }

        for (i in 0 .. Length(augmentedMessage) - width - 1) {
            Controlled LoadIBE(
                [augmentedMessage[i]],
                (poly, augmentedMessage[i + 1 .. i + width])
            );
        }
    }

    /// # Summary
    /// Runs a quantum implementation of CRC-8 (a.k.a. CRC-8-CCITT).
    /// 
    /// # Input
    /// ## input
    /// Qubit register containing input message.
    /// 
    /// ## output
    /// Qubit register to contain output checksum after the operation.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation CRC8 (
        input : Qubit[],
        output : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        CRC(8, 0x07, 0x00, input, output);
    }

    /// # Summary
    /// Runs a quantum implementation of CRC-16 (a.k.a. CRC-16-IBM,
    /// CRC-16/ARC).
    /// 
    /// # Input
    /// ## input
    /// Qubit register containing input message.
    /// 
    /// ## output
    /// Qubit register to contain output checksum after the operation.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation CRC16 (
        input : Qubit[],
        output : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        CRC(16, 0x8005, 0x0000, ReversedBytes(input), Reversed(output));
    }

    /// # Summary
    /// Runs a quantum implementation of CRC-32.
    /// 
    /// # Input
    /// ## input
    /// Qubit register containing input message.
    /// 
    /// ## output
    /// Qubit register to contain output checksum after the operation.
    /// 
    /// ## workspace
    /// Unused qubit register provided for interface consistency.
    operation CRC32 (
        input : Qubit[],
        output : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        CRC(32, 0x04C11DB7, 0xFFFFFFFF, ReversedBytes(input),
            Reversed(output));
        LoadI(0xFFFFFFFF, output);
    }
}
