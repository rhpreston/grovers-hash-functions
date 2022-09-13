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
    open Microsoft.Quantum.Math;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    // DEBUG must return false for full simulation compatibility.
    function DEBUG () : Bool { return false; }

    /// # Summary
    /// Converts an array into a 5x5x64 lane structure according to the Keccak
    /// specification. Note that each "lane" is in little-endian format.
    /// 
    /// # Input
    /// ## str
    /// Array to convert.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Data type of array.
    /// 
    /// # Output
    /// Array as Keccak lanes.
    /// 
    /// # See also
    /// Quicc.SHA3.LanesAsString
    function StringAsLanes<'T> (str : 'T[]) : 'T[][][] {
        let words = ArrayAsWords(64, str);
        mutable lanes = new 'T[][][0];
        for (x in 0 .. 4) {
            mutable col = new 'T[][0];
            for (y in 0 .. 4) {
                set col += [ReversedBytes(words[x + 5*y])];
            }
            set lanes += [col];
        }
        return lanes;
    }

    /// # Summary
    /// Converts Keccak lanes back into an array.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 lane structure.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Data type of lanes
    /// 
    /// # Output
    /// Keccak lanes as an array.
    /// 
    /// # See also
    /// Quicc.SHA3.StringAsLanes
    function LanesAsString<'T> (lanes : 'T[][][]) : 'T[] {
        mutable str = new 'T[0];
        for (y in 0 .. 4) {
            for (x in 0 .. 4) {
                set str += ReversedBytes(lanes[x][y]);
            }
        }
        return str;
    }

    /// # Summary
    /// Helper operation to print the state array.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 lane structure.
    operation PrintLanes (lanes : Qubit[][][]) : Unit {
        for (x in 0 .. 4) {
            let y0 = MeasureL(lanes[x][0]);
            let y1 = MeasureL(lanes[x][1]);
            let y2 = MeasureL(lanes[x][2]);
            let y3 = MeasureL(lanes[x][3]);
            let y4 = MeasureL(lanes[x][4]);
            Message($"  {y0}  {y1}  {y2}  {y3}  {y4}");
        }
    }

    /// # Summary
    /// Performs the Keccak sponge function based on the specified parameters.
    /// Note that this operation does not support the general Keccak
    /// specification, but is sufficient for SHA-3. It is not recommended to
    /// invoke this operation directly. Instead, use convenience operations
    /// such as Quicc.SHA3.SHA3_256.
    /// 
    /// # Input
    /// ## rate
    /// Keccak rate parameter. For SHA-3, this is 1600 minus the capacity.
    /// 
    /// ## suffix
    /// Delimited suffix parameter.
    /// 
    /// ## input
    /// Input message encoded in big-endian format.
    /// 
    /// ## output
    /// Qubit register to store the output of the Keccak algorithm.
    /// 
    /// ## References
    /// - Keccak team website:
    ///     https://keccak.team/index.html
    /// - FIPS 202:
    ///     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    /// - Extended Keccak code package (XKCP):
    ///     https://github.com/XKCP/XKCP
    /// - Keccak tools:
    ///     https://github.com/KeccakTeam/KeccakTools
    operation Keccak (
        rate : Int,
        suffix : Int,
        input : Qubit[],
        output : Qubit[]
    ) : Unit is Adj {
        body (...) {
            let inputLength = Length(input);
            let outputLength = Length(output);

            using (workspace = Qubit[1600]) {
                mutable state = workspace;

                // Absorb input blocks
                let remainder = inputLength % rate;
                for (offset in 0 .. rate .. inputLength - remainder - 1) {
                    Xor(input[offset .. offset + rate - 1],
                        state[0 .. rate - 1]);
                    set state = KeccakF1600(state);
                }
                Xor(input[inputLength - remainder ...],
                    state[0 .. remainder - 1]);

                // Do padding and switch to squeezing phase
                LoadIBE(suffix, state[remainder .. remainder + 7]);
                X(state[rate - 8]);
                set state = KeccakF1600(state);

                // Squeeze out all the output blocks
                let outRemainder = outputLength % rate;
                for (offset in 0 .. rate .. outputLength - outRemainder - 1) {
                    let outBlockSize = MinI(outputLength - offset, rate);
                    Xor(state[0 .. rate - 1],
                        output[offset .. offset + rate - 1]);
                    set state = KeccakF1600(state);
                }
                Xor(state[0 .. outRemainder - 1],
                    output[outputLength - outRemainder ...]);

                // Undo everything so workspace qubits can be released
                for (i in 0 .. outputLength / rate) {
                    set state = AdjointKeccakF1600(state);
                }
                X(state[rate - 8]);
                LoadIBE(suffix, state[remainder .. remainder + 7]);
                Xor(input[inputLength - remainder ...],
                    state[0 .. remainder - 1]);
                for (offset in inputLength - remainder - rate .. -1*rate .. 0)
                {
                    set state = AdjointKeccakF1600(state);
                    Xor(input[offset .. offset + rate - 1],
                        state[0 .. rate - 1]);
                }
            }
        }

        adjoint self;
    }

    /// # Summary
    /// Performs the Keccak-f[1600] permutation.
    /// 
    /// # Input
    /// ## state
    /// 1600-qubit array containing the state of the Keccak permutation.
    /// 
    /// # Output
    /// Modified state array.
    /// 
    /// # See also
    /// Quicc.SHA3.AdjointKeccakF1600
    operation KeccakF1600 (state : Qubit[]) : Qubit[] {
        mutable lanes = StringAsLanes(state);
        for (round in 0 .. 23) {
            if (DEBUG()) {
                Message($" Round {round}:");
                PrintLanes(lanes);
            }

            Theta(lanes);
            set lanes = RhoPi(lanes);
            Chi(lanes);
            Iota(round, lanes);
        }
        return LanesAsString(lanes);
    }

    /// # Summary
    /// Performs the inverse Keccak-f[1600] permutation.
    /// 
    /// # Input
    /// ## state
    /// 1600-qubit array containing the state of the Keccak permutation.
    /// 
    /// # Output
    /// Modified state array.
    /// 
    /// # See also
    /// Quicc.SHA3.KeccakF1600
    operation AdjointKeccakF1600 (state : Qubit[]) : Qubit[] {
        mutable lanes = StringAsLanes(state);
        for (round in 23 .. -1 .. 0) {
            Adjoint Iota(round, lanes);
            Adjoint Chi(lanes);
            set lanes = ReverseRhoPi(lanes);
            Adjoint Theta(lanes);

            if (DEBUG()) {
                Message($" Round {round}:");
                PrintLanes(lanes);
            }
        }
        return LanesAsString(lanes);
    }

    /// # Summary
    /// Performs the Theta function of the Keccak permutation.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 qubit array representing the state.
    /// 
    /// # Remarks
    /// After the state is modified, the function is inverted so the ancillary
    /// qubits can be released.
    operation Theta (lanes : Qubit[][][]) : Unit is Adj + Ctl {
        using (temp = Qubit[320]) {
            // Compute column parities
            let cols = ArrayAsWords(64, temp);
            for (x in 0 .. 4) {
                for (y in 0 .. 4) {
                    Xor(lanes[(x + 4) % 5][y], cols[x]);
                    Xor(RightRotate(lanes[(x + 1) % 5][y], 1), cols[x]);
                }
            }

            // Xor parities into the state array
            for (x in 0 ..4) {
                for (y in 0 .. 4) {
                    Xor(cols[x], lanes[x][y]);
                }
            }

            // Now, `lanes` contains the correct result, but the temp qubits
            // cannot be released. Theta is invertible, so the column parities
            // can be computed from the output, allowing us to return the temp
            // qubits to 0. The following code is adapted from:
            // https://github.com/KeccakTeam/KeccakTools/blob/master/Sources/Keccak-f.h#L553
            let inversePositions = [
                0xDE26BC4D789AF134L,
                0x09AF135E26BC4D78L,
                0xEBC4D789AF135E26L,
                0x7135E26BC4D789AFL,
                0xCD789AF135E26BC4L
            ];
            for (z in 0 .. 63) {
                for (xOff in 0 .. 4) {
                    if ((inversePositions[xOff] >>> z &&& 1L) != 0L) {
                        for (x in 0 .. 4) {
                            for (y in 0 .. 4) {
                                let C = lanes[(x + 5 - xOff) % 5][y];
                                Xor(RightRotate(C, z), cols[x]);
                            }
                        }
                    }
                }
            }
        }
    }

    /// # Summary
    /// Performs the Rho and Pi functions of the Keccak permutation.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 array representing the state.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Data of `lanes`; assumed to be `Qubit`.
    /// 
    /// # Output
    /// Reordered 5x5x64 array.
    /// 
    /// # See also
    /// Quicc.SHA3.ReverseRhoPi
    function RhoPi<'T> (lanes : 'T[][][]) : 'T[][][] {
        let reordering = [
            [[0, 0,  0], [3, 0, 28], [1, 0,  1], [4, 0, 27], [2, 0, 62]],
            [[1, 1, 44], [4, 1, 20], [2, 1,  6], [0, 1, 36], [3, 1, 55]],
            [[2, 2, 43], [0, 2,  3], [3, 2, 25], [1, 2, 10], [4, 2, 39]],
            [[3, 3, 21], [1, 3, 45], [4, 3,  8], [2, 3, 15], [0, 3, 41]],
            [[4, 4, 14], [2, 4, 61], [0, 4, 18], [3, 4, 56], [1, 4,  2]]
        ];
        mutable newLanes = new 'T[][][0];
        for (x in 0 .. 4) {
            mutable col = new 'T[][0];
            for (y in 0 .. 4) {
                let xPrev = reordering[x][y][0];
                let yPrev = reordering[x][y][1];
                let rot = reordering[x][y][2];
                set col += [RightRotate(lanes[xPrev][yPrev], rot)];
            }
            set newLanes += [col];
        }
        return newLanes;
    }

    /// # Summary
    /// Reverses the Rho and Pi functions of the Keccak permutation.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 array representing the state.
    /// 
    /// # Type Parameters
    /// ## 'T
    /// Data of `lanes`; assumed to be `Qubit`.
    /// 
    /// # Output
    /// Reordered 5x5x64 array.
    /// 
    /// # See also
    /// Quicc.SHA3.RhoPi
    function ReverseRhoPi<'T> (lanes : 'T[][][]) : 'T[][][] {
        let reordering = [
            [[0, 0, 0], [1, 3, 36], [2, 1, 3], [3, 4, 41], [4, 2, 18]],
            [[0, 2, 1], [1, 0, 44], [2, 3, 10], [3, 1, 45], [4, 4, 2]],
            [[0, 4, 62], [1, 2, 6], [2, 0, 43], [3, 3, 15], [4, 1, 61]],
            [[0, 1, 28], [1, 4, 55], [2, 2, 25], [3, 0, 21], [4, 3, 56]],
            [[0, 3, 27], [1, 1, 20], [2, 4, 39], [3, 2, 8], [4, 0, 14]]
        ];
        mutable newLanes = new 'T[][][0];
        for (x in 0 .. 4) {
            mutable col = new 'T[][0];
            for (y in 0 .. 4) {
                let xNext = reordering[x][y][0];
                let yNext = reordering[x][y][1];
                let rot = reordering[x][y][2];
                set col += [LeftRotate(lanes[xNext][yNext], rot)];
            }
            set newLanes += [col];
        }
        return newLanes;
    }

    /// # Summary
    /// Performs the Chi function of the Keccak permutation.
    /// 
    /// # Input
    /// ## lanes
    /// 5x5x64 qubit array representing the state.
    /// 
    /// # Remarks
    /// After the state is modified, the function is inverted so the ancillary
    /// qubits can be released.
    operation Chi (lanes : Qubit[][][]) : Unit is Adj + Ctl {
        for (y in 0 .. 4) {
            using (temp = Qubit[320]) {
                let rows = ArrayAsWords(64, temp);

                // Copy rows
                for (x in 0 .. 4) {
                    Xor(lanes[x][y], rows[x]);
                }

                for (x in 0 .. 4) {
                    // lanes[x][y] = ~rows[x+1] & rows[x+2]
                    within {
                        Not(rows[(x + 1) % 5]);
                    }
                    apply {
                        And(rows[(x + 1) % 5], rows[(x + 2) % 5], lanes[x][y]);
                    }
                }

                // Return temp qubits to 0 by partially reversing Chi.
                // Adapted from:
                // https://github.com/KeccakTeam/KeccakTools/blob/master/Sources/Keccak-f.h#L519
                for (x in 0 .. 2 .. 6) {
                    within {
                        Not(lanes[(x + 1) % 5][y]);
                    }
                    apply {
                        And(
                            lanes[(x + 1) % 5][y],
                            rows[(x + 2) % 5],
                            rows[x % 5]
                        );
                    }
                    Xor(lanes[x % 5][y], rows[x % 5]);
                }

                // Compute rows[3] directly
                within {
                    Not(lanes[1][y]);
                    And(lanes[1][y], lanes[2][y], rows[0]);
                    Xor(lanes[0][y], rows[0]);
                    Not(lanes[4][y]);
                }
                apply {
                    And(lanes[4][y], rows[0], rows[3]);
                }
                Xor(lanes[3][y], rows[3]);
            }
        }
    }

    /// # Summary
    /// Performs the Iota function of the Keccak permutation.
    /// 
    /// # Input
    /// ## round
    /// Current round of the Keccak permutation
    /// 
    /// ## lanes
    /// 5x5x64 qubit array representing the state.
    operation Iota (round : Int, lanes : Qubit[][][]) : Unit is Adj + Ctl {
        let roundConstants = [
            0x0000000000000001L, 0x0000000000008082L,
            0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL,
            0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L,
            0x0000000080000001L, 0x8000000080008008L
        ];

        LoadL(roundConstants[round], lanes[0][0]);
    }
}
