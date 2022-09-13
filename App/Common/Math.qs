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

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;


    /// # Summary
    /// Applies CNOT to each pair of (control, target) qubits.
    /// 
    /// # Input
    /// ## control
    /// Register containing control qubits. Not changed by the operation.
    /// 
    /// ## target
    /// Register containing target qubits. Modified by the operation.
    operation Xor (control : Qubit[], target : Qubit[]) : Unit is Adj + Ctl {
        for (i in 0..Length(control) - 1)
        {
            CNOT(control[i], target[i]);
        }
    }

    /// # Summary
    /// Applies X to each qubit in the target register.
    /// 
    /// # Input
    /// ## target
    /// Register containing target qubits.
    operation Not (target : Qubit[]) : Unit is Adj + Ctl {
        for (i in 0..Length(target) - 1)
        {
            X(target[i]);
        }
    }

    /// # Summary
    /// Applies CCNOT to each triple of (control1, control2, target) qubits.
    /// 
    /// # Input
    /// ## control1
    /// First control register. Not changed by the operation.
    /// 
    /// ## control2
    /// Second control register. Not changed by the operation.
    /// 
    /// ## target
    /// Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
    /// contain (control1 AND control2) after the operation.
    operation And (
        control1 : Qubit[],
        control2 : Qubit[],
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        for (i in 0..Length(control1) - 1)
        {
            CCNOT(control1[i], control2[i], target[i]);
        }
    }

    /// # Summary
    /// Convenience operation implementing bitwise NOR.
    /// 
    /// # Input
    /// ## control1
    /// First control register. Not changed by the operation.
    /// 
    /// ## control2
    /// Second control register. Not changed by the operation.
    /// 
    /// ## target
    /// Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
    /// contain (control1 NOR control2) after the operation.
    operation Nor (
        control1 : Qubit[],
        control2 : Qubit[],
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        within {
            Not(control1);
            Not(control2);
        }
        apply {
            And(control1, control2, target);
        }
    }

    /// # Summary
    /// Convenience operation implementing bitwise OR.
    /// 
    /// # Input
    /// ## control1
    /// First control register. Not changed by the operation.
    /// 
    /// ## control2
    /// Second control register. Not changed by the operation.
    /// 
    /// ## target
    /// Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
    /// contain (control1 OR control2) after the operation.
    operation Or (
        control1 : Qubit[],
        control2 : Qubit[],
        target : Qubit[]
    ) : Unit is Adj + Ctl {
        Nor(control1, control2, target);
        Not(target);
    }
}
