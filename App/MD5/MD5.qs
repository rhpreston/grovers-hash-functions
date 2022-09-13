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

namespace Quicc.MD5 {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    // DEBUG must return false for full simulation compatibility.
    function DEBUG () : Bool { return false; }

    /// # Summary
    /// Number of workspace qubits needed to perform the MD5 algorithm.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function MD5WorkspaceRequirement (inputLength : Int) : Int {
        return WorkspaceRequirement(128, 512, 64, inputLength);
    }

    /// # Summary
    /// Represents the `s` array in the MD5 algorithm.
    /// 
    /// # Input
    /// ## i
    /// Index into the `s` array. Must be in [0..63].
    /// 
    /// # Output
    /// The value of `s[i]`.
    function ShiftAmount (i : Int) : Int
    {
        let s = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ];
        return s[i];
    }

    /// # Summary
    /// Returns the integer representation of the sine of `Input`. This is the
    /// `K` array in the MD5 algorithm.
    /// 
    /// # Input
    /// ## i
    /// Index into the `K` array. Must be in [0..63].
    /// 
    /// # Output
    /// `K[Index]`.
    function SineInt (i : Int) : Int
    {
        let K = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ];
        return K[i];
    }

    /// # Summary
    /// Returns the appropriate word-index into the current chunk based on the
    /// iterator value. This is the `g` in the MD5 algorithm.
    /// 
    /// # Input
    /// ## i
    /// Iterator value.
    /// 
    /// # Output
    /// Corresponding `g` value.
    function ChunkIndex (i : Int) : Int {
        if (i < 16) {
            return i;
        }
        elif (i < 32) {
            return (5*i + 1) % 16;
        }
        elif (i < 48) {
            return (3*i + 5) % 16;
        }
        else {
            return (7*i) % 16;
        }
    }

    /// # Summary
    /// Computes the MD5 digest of a qubit register encoding bytes in little-
    /// endian format. Logically identical to a classical implementation.
    /// 
    /// # Input
    /// ## input
    /// Input message to MD5 algorithm in big-endian format.
    /// 
    /// ## digest
    /// 128-qubit register to store the output of the MD5 algorithm.
    /// 
    /// ## workspace
    /// Qubit register to save the intermediate result of each chunk. Use
    /// `Quicc.MD5.MD5WorkspaceRequirement` to determine the appropriate
    /// length.
    /// 
    /// # References
    /// - Wikipedia:
    ///     https://en.wikipedia.org/wiki/MD5
    /// - RFC 1321:
    ///     https://tools.ietf.org/html/rfc1321
    /// - MD5 Hash Generator:
    ///     https://www.md5hashgenerator.com/
    operation MD5 (
        input : Qubit[],
        digest : Qubit[],
        workspace: Qubit[]
    ) : Unit is Adj {
        let inputLength = Length(input);

        let digestReversedBytes = ReversedBytes(digest);
        InitializeDigest(digestReversedBytes);

        using (appendix = Qubit[MessagePadLength(inputLength, 512, 64)]) {
            PadMessage(inputLength, 64, appendix);
            let message = ReversedBytes(input) + appendix;

            for (i in 0 .. Length(message)/512 - 1) {
                ProcessChunk(
                    message[i*512 .. i*512 + 511],
                    digestReversedBytes,
                    workspace[i*128 .. i*128 + 127]
                );
            }

            Adjoint PadMessage(inputLength, 64, appendix);
        }
    }

    /// # Summary
    /// Initializes MD5 digest register.
    /// 
    /// # Input
    /// ## digest
    /// 128-qubit register.
    operation InitializeDigest (digest : Qubit[]) : Unit is Adj + Ctl {
        LoadI(0x67452301, digest[ 0 ..  31]); // a0
        LoadI(0xefcdab89, digest[32 ..  63]); // b0
        LoadI(0x98badcfe, digest[64 ..  95]); // c0
        LoadI(0x10325476, digest[96 .. 127]); // d0
    }

    /// # Summary
    /// Processes a single 512-bit chunk in the MD5 algorithm. Measures and
    /// prints the contents of the virtual registers on every iteration if
    /// `DEBUG` returns `true`.
    /// 
    /// # Input
    /// ## chunk
    /// 512-qubit chunk of MD5 message to process.
    /// 
    /// ## digest
    /// 128-qubit register containing the state of the MD5 digest.
    /// 
    /// ## workspace
    /// 128-qubit register used to perform the computations.
    /// 
    /// # Remarks
    /// This operation implements a custom adjoint functor.
    operation ProcessChunk (
        chunk : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        body (...) {
            Xor(digest, workspace);

            mutable a = workspace[ 0.. 31];
            mutable b = workspace[32.. 63];
            mutable c = workspace[64.. 95];
            mutable d = workspace[96..127];
            mutable temp = new Qubit[0];

            let words = ArrayAsWords(32, chunk);

            if (DEBUG()) {
                Message("");
                Message(" --- PROCESSING CHUNK ---");
                Message("");
                Message("Words:");
                for (i in 0 .. Length(words) - 1) {
                    Message($" words[{i}] = {MeasureI(words[i])}");
                }
                Message("");
                Message("Rounds:");
            }

            for (i in 0 .. 63) {
                if (DEBUG()) {
                    Message(
                        $" [i = {i}] a={MeasureI(a)} b={MeasureI(b)}" +
                        $" c={MeasureI(c)} d={MeasureI(d)}"
                    );
                }

                ComputeRound(i, words, a, b, c, d);

                // Rotation is backward due to little-endianness
                set temp = RightRotate(a, ShiftAmount(i));
                Add(b, temp);

                set a = d;
                set d = c;
                set c = b;
                set b = temp;
            }

            Add(a, digest[ 0.. 31]);
            Add(b, digest[32.. 63]);
            Add(c, digest[64.. 95]);
            Add(d, digest[96..127]);

            if (DEBUG()) {
                Message(
                    $" [final] a={MeasureI(a)} b={MeasureI(b)}" +
                    $" c={MeasureI(c)} d={MeasureI(d)}"
                );
                Message("");
                Message("Digest state:");
                Message($" a0 = {MeasureI(digest[0..31])}");
                Message($" b0 = {MeasureI(digest[32..63])}");
                Message($" c0 = {MeasureI(digest[64..95])}");
                Message($" d0 = {MeasureI(digest[96..127])}");
            }
        }

        adjoint (...) {
            // The aggregate rotation of all the MD5 rounds is equivalent to
            // `LeftRotate(register, 8)` for a, b, and c and
            // `RightRotate(register, 8)` for d.
            mutable a = LeftRotate(workspace[ 0.. 31], 8);
            mutable b = LeftRotate(workspace[32.. 63], 8);
            mutable c = LeftRotate(workspace[64.. 95], 8);
            mutable d = RightRotate(workspace[96..127], 8);
            mutable temp = new Qubit[0];

            let words = ArrayAsWords(32, chunk);

            if (DEBUG()) {
                Message("");
                Message(" --- PROCESSING CHUNK (adjoint) ---");
                Message("");
                Message("Words:");
                for (i in 0 .. Length(words) - 1) {
                    Message($" words[{i}] = {MeasureI(words[i])}");
                }
                Message("");
                Message("Digest state:");
                Message($" a0 = {MeasureI(digest[0..31])}");
                Message($" b0 = {MeasureI(digest[32..63])}");
                Message($" c0 = {MeasureI(digest[64..95])}");
                Message($" d0 = {MeasureI(digest[96..127])}");
                Message("");
                Message("Rounds:");
                Message(
                    $" [final] a={MeasureI(a)} b={MeasureI(b)}" +
                    $" c={MeasureI(c)} d={MeasureI(d)}"
                );
            }

            Adjoint Add(a, digest[ 0.. 31]);
            Adjoint Add(b, digest[32.. 63]);
            Adjoint Add(c, digest[64.. 95]);
            Adjoint Add(d, digest[96..127]);

            for (i in 63 .. -1 .. 0) {
                set temp = b;
                set b = c;
                set c = d;
                set d = a;

                Adjoint Add(b, temp);
                set a = LeftRotate(temp, ShiftAmount(i));

                Adjoint ComputeRound(i, words, a, b, c, d);

                if (DEBUG()) {
                    Message(
                        $" [i = {i}] a={MeasureI(a)} b={MeasureI(b)}" +
                        $" c={MeasureI(c)} d={MeasureI(d)}"
                    );
                }
            }

            Adjoint Xor(digest, workspace);
        }
    }

    /// # Summary
    /// Computes a round of the MD5 algorithm. Performed in-place, such that
    /// `a` contains `F + A + K[i] + M[g]` after the operation.
    /// 
    /// # Input
    /// ## i
    /// Iterator value.
    /// 
    /// ## words
    /// Array of 32-qubit words derived from the current chunk.
    /// 
    /// ## a
    /// 32-qubit virtual register.
    /// 
    /// ## b
    /// 32-qubit virtual register.
    /// 
    /// ## c
    /// 32-qubit virtual register.
    /// 
    /// ## d
    /// 32-qubit virtual register.
    operation ComputeRound (
        i : Int,
        words : Qubit[][],
        a : Qubit[],
        b : Qubit[],
        c : Qubit[],
        d : Qubit[]
    ) : Unit is Adj + Ctl {
        if (i < 16) {
            // a += Choice(b, c, d)
            Choice(b, c, d);
            Add(d, a);
            Adjoint Choice(b, c, d);
        }
        elif (i < 32) {
            // a += Choice(d, b, c)
            Choice(d, b, c);
            Add(c, a);
            Adjoint Choice(d, b, c);
        }
        elif (i < 48) {
            // a += b xor c xor d
            Xor(b, d);
            Xor(c, d);
            Add(d, a);
            Adjoint Xor(b, d);
            Adjoint Xor(c, d);
        }
        else {
            // a += (not c) xor ((not b) and d)
            Not(b);
            Not(c);
            And(b, d, c);
            Add(c, a);
            Adjoint And(b, d, c);
            Adjoint Not(b);
            Adjoint Not(c);
        }

        Add(words[ChunkIndex(i)], a);
        AddConstantNoPhase(SineInt(i), a);
    }
}
