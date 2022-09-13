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
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Intrinsic;


    /// # Summary
    /// Breaks up a flat array into an array of words with specified
    /// length.
    /// 
    /// # Input
    /// ## wordLength
    /// Number of elements per word.
    /// 
    /// ## array
    /// Array to break up.
    /// 
    /// # Output
    /// Array of arrays.
    function ArrayAsWords<'T> (
        wordLength : Int,
        array : 'T[]
    ) : 'T[][] {
        if (Length(array) == 0) { return [new 'T[0]]; }
        if (Length(array) % wordLength != 0) {
            fail $"Length of array must be a multiple of {wordLength}";
        }
        mutable words = [array[0 .. wordLength - 1]];
        for (i in wordLength .. wordLength .. Length(array) - 1) {
            set words += [array[i .. i + wordLength - 1]];
        }
        return words;
    }

    /// # Summary
    /// Reverses the order of every 8 elements in the array. This has the
    /// effect of toggling between big- and little-endian byte encoding.
    /// 
    /// # Input
    /// ## Array
    /// Array to reverse the byte endianness in.
    /// 
    /// # Output
    /// Array with reordering.
    function ReversedBytes<'T> (array : 'T[]) : 'T[] {
        mutable reversedBytes = new 'T[0];
        let bytes = ArrayAsWords(8, array);
        for (eachByte in bytes) {
            set reversedBytes += Reversed(eachByte);
        }
        return reversedBytes;
    }

    /// # Summary
    /// Loads a boolean array into a qubit register. Applies X to indices that
    /// contain `true`.
    /// 
    /// # Input
    /// ## value
    /// Boolean array to load into register.
    /// 
    /// ## target
    /// Qubit register to load `value` into.
    /// 
    /// # Remarks
    /// Does not fail if `value` and `target` have different lengths.
    /// 
    /// # See also
    /// - Quicc.Common.LoadI
    /// - Quicc.Common.LoadIBE
    /// - Quicc.Common.LoadL
    /// - Quicc.Common.LoadLBE
    operation LoadBoolArray (
        value : Bool[],
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        let length = Min([Length(value), Length(target)]);
        for (i in 0 .. length - 1) {
            if (value[i]) {
                X(target[i]);
            }
        }
    }

    /// # Summary
    /// Loads an integer into a qubit register in little-endian format. Can
    /// also be used to toggle qubits with a bitmask.
    /// 
    /// # Input
    /// ## value
    /// Number to load into register. Must be positive and less than 2^63.
    /// 
    /// ## target
    /// Qubit register to load `value` into.
    /// 
    /// # Remarks
    /// This operation is a wrapper for
    /// Microsoft.Quantum.Arithmetic.ApplyXorInPlace.
    /// 
    /// # See also
    /// - Quicc.Common.LoadBoolArray
    /// - Quicc.Common.LoadIBE
    /// - Quicc.Common.LoadL
    /// - Quicc.Common.LoadLBE
    operation LoadI (value : Int, target : Qubit[]) : Unit is Adj + Ctl {
        ApplyXorInPlace(value, LittleEndian(target));
    }

    /// # Summary
    /// Loads an integer into a qubit register in big-endian format. Can
    /// also be used to toggle qubits with a bitmask.
    /// 
    /// # Input
    /// ## value
    /// Number to load into register. Must be positive and less than 2^63.
    /// 
    /// ## target
    /// Qubit register to load `value` into.
    /// 
    /// # See also
    /// - Quicc.Common.LoadBoolArray
    /// - Quicc.Common.LoadI
    /// - Quicc.Common.LoadL
    /// - Quicc.Common.LoadLBE
    operation LoadIBE (value : Int, target : Qubit[]) : Unit is Adj + Ctl {
        ApplyXorInPlace(value, LittleEndian(Reversed(target)));
    }

    /// # Summary
    /// Loads a big integer into a qubit register in little-endian format. Can
    /// also be used to toggle qubits with a bitmask.
    /// 
    /// # Input
    /// ## value
    /// Positive number to load into register.
    /// 
    /// ## target
    /// Qubit register to load `value` into.
    /// 
    /// # Remarks
    /// The operation will not fail if `value` is negative, but the data will
    /// not be interpreted correctly when it is read later.
    /// 
    /// # See also
    /// - Quicc.Common.LoadBoolArray
    /// - Quicc.Common.LoadI
    /// - Quicc.Common.LoadIBE
    /// - Quicc.Common.LoadLBE
    operation LoadL (value : BigInt, target : Qubit[]) : Unit is Adj + Ctl {
        LoadBoolArray(BigIntAsBoolArray(value), target);
    }

    /// # Summary
    /// Loads a big integer into a qubit register in big-endian format. Can
    /// also be used to toggle qubits with a bitmask.
    /// 
    /// # Input
    /// ## value
    /// Positive number to load into register.
    /// 
    /// ## target
    /// Qubit register to load `value` into.
    /// 
    /// # Remarks
    /// The operation will not fail if `value` is negative, but the data will
    /// not be interpreted correctly when it is read later.
    /// 
    /// # See also
    /// - Quicc.Common.LoadBoolArray
    /// - Quicc.Common.LoadI
    /// - Quicc.Common.LoadIBE
    /// - Quicc.Common.LoadL
    operation LoadLBE (value : BigInt, target : Qubit[]) : Unit is Adj + Ctl {
        LoadBoolArray(BigIntAsBoolArray(value), Reversed(target));
    }
}
