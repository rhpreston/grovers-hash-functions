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

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Measurement;


    /// # Summary
    /// Measures each qubit in a register and returns the results as a Bool
    /// array, where `One` is mapped to `true` and `Zero` is mapped to `false`.
    /// 
    /// # Input
    /// ## target
    /// Qubit register to measure.
    /// 
    /// # Output
    /// Bool array containing result of each measurement.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArray
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureBoolArray (target: Qubit[]) : Bool[] {
        return ResultArrayAsBoolArray(MultiM(target));
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as an
    /// integer in little-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register in little-endian format.
    /// 
    /// # Output
    /// Unsigned integer containing interpreted result of measurement.
    /// 
    /// # Remarks
    /// This operation is distinct from
    /// Microsoft.Quantum.Arithmetic.MeasureInteger in two ways:
    /// - It does not reset the input register to the $\ket{00\cdots 0}$ state
    /// - It relaxes the input type to `Qubit[]`
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArray
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureI (target: Qubit[]) : Int {
        return ResultArrayAsInt(MultiM(target));
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as an
    /// integer in big-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register in big-endian format.
    /// 
    /// # Output
    /// Unsigned integer containing interpreted result of measurement.
    /// 
    /// # Remarks
    /// This operation does not reset the input register to the
    /// $\ket{00\cdots 0}$ state.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArray
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureIBE (target: Qubit[]) : Int {
        return ResultArrayAsInt(Reversed(MultiM(target)));
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as a
    /// positive big integer in little-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register in little-endian format.
    /// 
    /// # Output
    /// Positive big integer containing interpreted result of measurement.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArray
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureL (target: Qubit[]) : BigInt {
        return BoolArrayAsBigInt(MeasureBoolArray(target) + [false]);
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as a
    /// positive big integer in big-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register in big-endian format.
    /// 
    /// # Output
    /// Positive big integer containing interpreted result of measurement.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureByteArray
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureLBE (target: Qubit[]) : BigInt {
        return BoolArrayAsBigInt(Reversed(MeasureBoolArray(target)) + [false]);
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as an array
    /// of bytes with each byte in little-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register encoding bytes.
    /// 
    /// # Output
    /// Array of integers representing bytes.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArrayBE
    operation MeasureByteArray (target: Qubit[]) : Int[] {
        if (Length(target) % 8 != 0) {
            fail "Target length must be a multiple of 8";
        }
        mutable bytes = new Int[0];
        for (i in 0 .. 8 .. Length(target) - 1) {
            set bytes += [MeasureI(target[i .. i + 7])];
        }
        return bytes;
    }

    /// # Summary
    /// Measures each qubit in a register and interprets the result as an array
    /// of bytes with each byte in big-endian format.
    /// 
    /// # Input
    /// ## target
    /// Qubit register encoding bytes.
    /// 
    /// # Output
    /// Array of integers representing bytes.
    /// 
    /// # See also
    /// - Quicc.Common.MeasureBoolArray
    /// - Quicc.Common.MeasureI
    /// - Quicc.Common.MeasureIBE
    /// - Quicc.Common.MeasureL
    /// - Quicc.Common.MeasureLBE
    /// - Quicc.Common.MeasureByteArray
    operation MeasureByteArrayBE (target: Qubit[]) : Int[] {
        if (Length(target) % 8 != 0) {
            fail "Target length must be a multiple of 8";
        }
        mutable bytes = new Int[0];
        for (i in 0 .. 8 .. Length(target) - 1) {
            set bytes += [MeasureI(target[i + 7 .. -1 .. i])];
        }
        return bytes;
    }
}
