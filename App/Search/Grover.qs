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

namespace Quicc.Search {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Intrinsic;
    open Microsoft.Quantum.Math;

    open Quicc.Common;


    /// # Summary
    /// Returns the number of iterations in Grover's algorithm that maximizes
    /// the probability of success.
    /// 
    /// # Input
    /// ## numQubits
    /// Number of input qubits that will be searched over.
    /// 
    /// ## numTargets
    /// Number of search targets.
    /// 
    /// # Output
    /// Optimal number of iterations.
    function NumIterations (numQubits : Int, numTargets : Int) : Int {
        let sqrtN = PowD(2., IntAsDouble(numQubits) / 2.);
        let sqrtK = Sqrt(IntAsDouble(numTargets));
        let theta = ArcSin(sqrtK / sqrtN);
        let optimum = 0.25 * PI() / theta;

        if (optimum >= PowD(2., 63.)) {
            fail "More than 2^63 iterations is not currently supported";
        }

        return Floor(optimum);
    }

    /// # Summary
    /// Uses Grover's algorithm to find a corresponding input to an operation
    /// that matches a given output.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. For example, to try Grover's algorithm
    /// with 1 search target and then try 2 if that fails, use `[1, 2]`.
    /// 
    /// ## inputLength
    /// Number of qubits in the input (search space).
    /// 
    /// ## outputLength
    /// Number of output qubits in the operation.
    /// 
    /// ## workspaceLength
    /// Number of extra qubits needed for the operation.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// ## op
    /// Operation taking 3 qubit arrays in order `(input, output, workspace)`.
    /// Must support the adjoint functor.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation PerformSearchOnOp (
        numSearchTargets : Int[],
        inputLength : Int,
        outputLength: Int,
        workspaceLength: Int,
        outputToMatch : BigInt,
        op : ((Qubit[], Qubit[], Qubit[]) => Unit is Adj)
    ) : BigInt {
        // Transform operation into a phase-flip oracle
        let oracle = OpAsOracle(outputLength, workspaceLength, outputToMatch,
                                op, _, _);

        for (numTargets in numSearchTargets) {
            let numIterations = NumIterations(inputLength, numTargets);

            using (input = Qubit[inputLength]) {
                RunGroverOnOracle(numIterations, oracle, input);

                // Measure the result of Grover's algorithm
                let result = MeasureL(Reversed(input));

                // Check if it succeeded
                let done = CheckSearchResult(oracle, input);

                ResetAll(input);

                if (done) { return result; }
            }
        }
        // If we get here, the search failed
        return -1L;
    }

    /// # Summary
    /// Transforms an operation into an oracle that phase-flips a target qubit
    /// (Z gate) conditional on the output of the operation matching a
    /// specified value.
    /// 
    /// # Input
    /// ## outputLength
    /// Number of output qubits in the operation.
    /// 
    /// ## workspaceLength
    /// Number of extra qubits needed for the operation.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output value that will cause the target
    /// qubit to be phase-flipped
    /// 
    /// ## op
    /// Operation taking 3 qubit arrays in order `(input, output, workspace)`.
    /// Must support the adjoint functor.
    /// 
    /// ## input
    /// Input qubit register.
    /// 
    /// ## target
    /// Target qubit.
    /// 
    /// # Remarks
    /// To produce an oracle operation, leave the `input` and `target`
    /// parameters as `_`.
    operation OpAsOracle (
        outputLength : Int,
        workspaceLength : Int,
        outputToMatch : BigInt,
        op : ((Qubit[], Qubit[], Qubit[]) => Unit is Adj),
        input : Qubit[],
        target : Qubit
    ) : Unit is Adj {
        using ((output, workspace) = (
            Qubit[outputLength],
            Qubit[workspaceLength]
        )) {
            // Calculate where the output must be 0 to match
            let outputMask = outputToMatch * -1L - 1L;

            within {
                op(input, output, workspace);

                // Toggle the qubits corresponding with the mask
                LoadLBE(outputMask, output);
            }
            apply {
                // The output matches if and only if all the qubits are 1
                Controlled Z(output, target);
            }
        }
    }

    /// # Summary
    /// Runs Grover's algorithm on a phase-flip oracle.
    /// 
    /// # Input
    /// ## numIterations
    /// Number of times to perform amplitude amplification.
    /// 
    /// ## oracle
    /// Operation that phase-flips a target qubit conditional on a qubit
    /// register. Must support the adjoint functor.
    /// 
    /// ## input
    /// Qubit register to input to the oracle on each iteration. Will contain
    /// the result of the algorithm after the operation.
    operation RunGroverOnOracle (
        numIterations : Int,
        oracle : ((Qubit[], Qubit) => Unit is Adj),
        input : Qubit[]
    ) : Unit is Adj {
        using (target = Qubit()) {
            ApplyToEachA(H, input);
            X(target);

            for (i in 1..numIterations) {
                oracle(input, target);

                within {
                    ApplyToEachA(H, input);
                    ApplyToEachA(X, input);
                }
                apply {
                    Controlled Z(input, target);
                }
            }

            X(target);
        }
    }

    /// # Summary
    /// Determines if a given input causes an oracle to phase-flip a target
    /// qubit.
    /// 
    /// # Input
    /// ## oracle
    /// Operation that phase-flips a target qubit conditional on a qubit
    /// register.
    /// 
    /// ## input
    /// Qubit register to input to the oracle.
    /// 
    /// # Output
    /// `true` if the target is phase-flipped; `false` otherwise.
    operation CheckSearchResult (
        oracle : ((Qubit[], Qubit) => Unit),
        input : Qubit[]
    ) : Bool {
        using (target = Qubit()) {
            H(target);
            oracle(input, target);
            H(target);

            if (M(target) == One) {
                X(target);
                return true;
            }
            else {
                return false;
            }
        }
    }
}
