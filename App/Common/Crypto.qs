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

namespace Quicc.Common {

    open Microsoft.Quantum.Arithmetic;
    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Intrinsic;


    /// # Summary
    /// Number of workspace qubits needed to perform the hash function.
    /// 
    /// # Input
    /// ## digestLength
    /// Qubit-length of message digest, i.e., number of qubits required per
    /// chunk.
    /// 
    /// ## chunkLength
    /// Qubit-length of a single chunk.
    /// 
    /// ## encodeLength
    /// Number of qubits needed to encode the message length.
    /// 
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function WorkspaceRequirement (
        digestLength : Int,
        chunkLength : Int,
        encodeLength : Int,
        inputLength : Int
    ) : Int {
        return ((inputLength + encodeLength)/chunkLength + 1) * digestLength;
    }

    /// # Summary
    /// Number of qubits to append to the input message to a hash function.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// ## chunkLength
    /// Qubit-length of a chunk in the hash function
    /// 
    /// ## encodeLength
    /// Number of qubits needed to encode the message length.
    /// 
    /// # Output
    /// Number of qubits to pad.
    /// 
    /// # Remarks
    /// The formula uses modular arithmetic to ensure the result is at least
    /// `encodeLength + 1`, and the total length of the padded message is a
    /// multiple of `chunkLength`.
    function MessagePadLength (
        inputLength : Int,
        chunkLength : Int,
        encodeLength : Int
    ) : Int {
        let numExtraZeros = chunkLength - encodeLength - inputLength - 1;
        return (numExtraZeros &&& (chunkLength - 1)) + encodeLength + 1;
    }

    /// # Summary
    /// Does preprocessing step for hash functions using little-endian
    /// encoding.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// ## encodeLength
    /// Number of qubits to encode `inputLength` in.
    /// 
    /// ## appendix
    /// Register containing message pad qubits. Use
    /// Quicc.Common.MessagePadLength to determine the appropriate length.
    /// 
    /// # See also
    /// - Quicc.Common.PadMessageBE
    operation PadMessage (
        inputLength : Int,
        encodeLength : Int,
        appendix : Qubit[]
    ) : Unit is Adj + Ctl {
        // The first byte after the original message should be 0x80
        let byteAlignment = (8 - inputLength) &&& 0x7;
        LoadI(0x80, appendix[byteAlignment .. byteAlignment + 7]);

        // Encode `inputLength` in the last `encodeLength` qubits
        LoadL(
            IntAsBigInt(inputLength),
            appendix[Length(appendix) - encodeLength ...]
        );
    }

    /// # Summary
    /// Does preprocessing step for hash functions using big-endian encoding.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// ## encodeLength
    /// Number of qubits to encode `inputLength` in.
    /// 
    /// ## appendix
    /// Register containing message pad qubits. Use
    /// Quicc.Common.MessagePadLength to determine the appropriate length.
    /// 
    /// # See also
    /// - Quicc.Common.PadMessage
    operation PadMessageBE (
        inputLength : Int,
        encodeLength : Int,
        appendix : Qubit[]
    ) : Unit is Adj + Ctl {
        // The first byte after the original message should be 0x80
        let byteAlignment = (8 - inputLength) &&& 0x7;
        LoadIBE(0x80, appendix[byteAlignment .. byteAlignment + 7]);

        // Encode `inputLength` in the last `encodeLength` qubits
        LoadLBE(
            IntAsBigInt(inputLength),
            appendix[Length(appendix) - encodeLength ...]
        );
    }

    /// # Summary
    /// Shifts an array to the left in a circular manner by a given amount.
    /// I.e., elements that "fall off" the left are "fed into" the right.
    /// 
    /// # Input
    /// ## array
    /// Array to rotate.
    /// 
    /// ## amount
    /// Amount to rotate by.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Type of array values.
    /// 
    /// # Output
    /// Rotated array.
    /// 
    /// # See also
    /// - Quicc.App.Common.RightRotate
    function LeftRotate<'T> (array : 'T[], amount : Int) : 'T[] {
        return array[amount ...] + array[0 .. amount - 1];
    }

    /// # Summary
    /// Shifts an array to the right in a circular manner by a given amount.
    /// I.e., elements that "fall off" the right are "fed into" the left.
    /// 
    /// # Input
    /// ## array
    /// Array to rotate.
    /// 
    /// ## amount
    /// Amount to rotate by.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Type of array values.
    /// 
    /// # Output
    /// Rotated array.
    /// 
    /// # See also
    /// - Quicc.App.Common.RightRotate
    function RightRotate<'T> (array : 'T[], amount : Int) : 'T[] {
        return LeftRotate(array, Length(array) - amount);
    }

    /// # Summary
    /// Applies in-place bitwise choice operation to 3 qubit registers. If the
    /// control is 1, the first choice is selected; if it is 0, the second
    /// choice.
    /// 
    /// # Input
    /// ## control
    /// Control register. Not changed by the operation.
    /// 
    /// ## choice1
    /// Register containing first choice. Not changed by the operation.
    /// 
    /// ## choice2
    /// Register containing second choice. For each qubit in `control` that is
    /// a 1, the corresponding qubit will be changed to that in `choice1`.
    operation Choice (
        control : Qubit[],
        choice1 : Qubit[],
        choice2 : Qubit[]
    ) : Unit is Adj + Ctl {
        Xor(choice2, choice1);
        And(control, choice1, choice2);
        Adjoint Xor(choice2, choice1);
    }

    /// # Summary
    /// Applies in-place bitwise majority operation to 3 qubit registers. If at
    /// least two of the inputs are 1, the output will be 1.
    /// 
    /// # Input
    /// ## input1
    /// First input register. Not changed by the operation.
    /// 
    /// ## input2
    /// Second input register. Not changed by the operation.
    /// 
    /// ## input3
    /// Third input register. Contains the output after the operation.
    operation Majority (
        input1 : Qubit[],
        input2 : Qubit[],
        input3 : Qubit[]
    ) : Unit is Adj + Ctl {
        for (i in 0 .. Length(input1) - 1)
        {
            MAJ(input1[i], input2[i], input3[i]);
        }
    }
}
