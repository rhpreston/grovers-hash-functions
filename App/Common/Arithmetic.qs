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
// ==========================================================================

namespace Quicc.Common {
    
    open Microsoft.Quantum.Arithmetic;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;


    /// # Summary
    /// Performs an in-place addition of two qubit registers containing
    /// integers represented in little-endian format.
    /// 
    /// # Input
    /// ## addend
    /// Addend register. Not changed by the operation.
    /// 
    /// ## target
    /// Target register. Contains the sum after the operation.
    operation Add (addend : Qubit[], target : Qubit[]) : Unit is Adj + Ctl {
        RippleCarryAdderNoCarryTTK(LittleEndian(addend), LittleEndian(target));
    }
    
    /// # Summary
    /// Performs an in-place addition of two qubit registers containing
    /// integers represented in big-endian format.
    /// 
    /// # Input
    /// ## addend
    /// Addend register. Not changed by the operation.
    /// 
    /// ## target
    /// Target register. Contains the sum after the operation.
    operation AddBE (addend : Qubit[], target : Qubit[]) : Unit is Adj + Ctl {
        RippleCarryAdderNoCarryTTK(
            BigEndianAsLittleEndian(BigEndian(addend)),
            BigEndianAsLittleEndian(BigEndian(target))
        );
    }

    /// # Summary
    /// Performs an in-place addition of an integer constant and a qubit
    /// register containing an integer represented in little-endian format.
    /// 
    /// # Input
    /// ## addend
    /// Number to increment `target`.
    /// 
    /// ## target
    /// Target register. Contains the sum after the operation.
    /// 
    /// # Remarks
    /// More efficient arithmetic adders exist that utilize phase operations,
    /// but these are incompatible with the Toffoli simulator.
    /// 
    /// # See also
    /// - Quicc.Common.AddConstantNoPhaseL
    operation AddConstantNoPhase (
        addend : Int,
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        using (temp = Qubit[Length(target)]) {
            LoadI(addend, temp);
            Add(temp, target);
            Adjoint LoadI(addend, temp);
        }
    }

    /// # Summary
    /// Performs an in-place addition of a big integer constant and a qubit
    /// register containing an integer represented in little-endian format.
    /// 
    /// # Input
    /// ## addend
    /// Number to increment `target`.
    /// 
    /// ## target
    /// Target register. Contains the sum after the operation.
    /// 
    /// # Remarks
    /// More efficient arithmetic adders exist that utilize phase operations,
    /// but these are incompatible with the Toffoli simulator.
    /// 
    /// # See also
    /// - Quicc.Common.AddConstantNoPhase
    operation AddConstantNoPhaseL (
        addend : BigInt,
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        using (temp = Qubit[Length(target)]) {
            LoadL(addend, temp);
            Add(temp, target);
            Adjoint LoadL(addend, temp);
        }
    }
}
