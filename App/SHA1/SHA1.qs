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

namespace Quicc.SHA1 {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    // DEBUG must return false for full simulation compatibility.
    function DEBUG () : Bool { return false; }

    /// # Summary
    /// Number of workspace qubits needed to perform the SHA-1 algorithm.
    /// 
    /// # Input
    /// ## inputLength
    /// Qubit-length of input message.
    /// 
    /// # Output
    /// Number of workspace qubits required.
    function SHA1WorkspaceRequirement (inputLength : Int) : Int {
        return WorkspaceRequirement(160, 512, 64, inputLength);
    }

    /// # Summary
    /// Computes the SHA-1 digest of a qubit register encoding bytes in little-
    /// endian format. Logically identical to a classical implementation.
    /// 
    /// # Input
    /// ## input
    /// Input message to the SHA-1 algorithm in big-endian format.
    /// 
    /// ## digest
    /// 160-qubit register to store the output of the SHA-1 algorithm.
    /// 
    /// ## workspace
    /// Qubit register to save the intermediate result of each chunk. Use
    /// `Quicc.SHA1.SHA1WorkspaceRequirement` to determine the
    /// appropriate length.
    ///
    /// # References
    /// - Wikipedia:
    ///     https://en.wikipedia.org/wiki/SHA-1
    /// - Example Python implementation:
    ///     https://github.com/ajalt/python-sha1
    /// - SHA-1 Hash Generator:
    ///     http://www.sha1-online.com/
    operation SHA1 (
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let inputLength = Length(input);

        InitializeDigest(digest);

        using (appendix = Qubit[MessagePadLength(inputLength, 512, 64)]) {
            PadMessageBE(inputLength, 64, appendix);
            let message = input + appendix;

            for (i in 0 .. Length(message)/512 - 1) {
                ProcessChunk(
                    message[i*512 .. i*512 + 511],
                    digest,
                    workspace[i*160 .. i*160 + 159]
                );
            }

            Adjoint PadMessageBE(inputLength, 64, appendix);
        }
    }

    /// # Summary
    /// Initializes SHA-1 digest register.
    /// 
    /// # Input
    /// ## digest
    /// 160-qubit register.
    operation InitializeDigest (digest : Qubit[]) : Unit is Adj + Ctl {
        LoadIBE(0x67452301, digest[  0 ..  31]); // h0
        LoadIBE(0xEFCDAB89, digest[ 32 ..  63]); // h1
        LoadIBE(0x98BADCFE, digest[ 64 ..  95]); // h2
        LoadIBE(0x10325476, digest[ 96 .. 127]); // h3
        LoadIBE(0xC3D2E1F0, digest[128 .. 159]); // h4
    }

    /// # Summary
    /// Processes a single 512-bit chunk in the SHA-1 algorithm. Measures and
    /// prints the contents of the virtual registers on every iteration if
    /// `DEBUG` returns `true`.
    /// 
    /// # Input
    /// ## chunk
    /// 512-qubit chunk of SHA-1 message to process.
    /// 
    /// ## digest
    /// 160-qubit register containing the state of the SHA-1 digest.
    /// 
    /// ## workspace
    /// 160-qubit register used to perform the computations.
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

            mutable a = workspace[ 31 .. -1 ..  0];
            mutable b = workspace[ 63 .. -1 .. 32];
            mutable c = workspace[ 95 .. -1 .. 64];
            mutable d = workspace[127 .. -1 .. 96];
            mutable e = workspace[159 .. -1 ..128];
            mutable temp = new Qubit[0];

            using (extension = Qubit[2048]) {
                let words = ArrayAsWords(32, chunk + extension);
                ExtendWords(words);

                if (DEBUG()) {
                    Message("");
                    Message(" --- PROCESSING CHUNK ---");
                    Message("");
                    Message("Words:");
                    for (i in 0 .. Length(words) - 1) {
                        Message($" words[{i}] = {MeasureI(Reversed(words[i]))}");
                    }
                    Message("");
                    Message("Rounds:");
                }

                for (i in 0 .. 79) {
                    if (DEBUG()) {
                        Message(
                            $" [i = {i}] a={MeasureI(a)} b={MeasureI(b)}" +
                            $" c={MeasureI(c)} d={MeasureI(d)} e={MeasureI(e)}"
                        );
                    }

                    ComputeRound(i, words, b, c, d, e);

                    // Rotation is backward due to little-endianness
                    set temp = e;
                    Add(RightRotate(a, 5), temp);

                    set e = d;
                    set d = c;
                    set c = RightRotate(b, 30);
                    set b = a;
                    set a = temp;
                }

                Adjoint ExtendWords(words);
            }

            Add(a, digest[ 31 .. -1 ..  0]);
            Add(b, digest[ 63 .. -1 .. 32]);
            Add(c, digest[ 95 .. -1 .. 64]);
            Add(d, digest[127 .. -1 .. 96]);
            Add(e, digest[159 .. -1 ..128]);

            if (DEBUG()) {
                Message(
                    $" [final] a={MeasureI(a)} b={MeasureI(b)}" +
                    $" c={MeasureI(c)} d={MeasureI(d)} e={MeasureI(e)}"
                );
                Message("");
                Message("Digest state:");
                Message($" h0 = {MeasureI(digest[31..-1..0])}");
                Message($" h1 = {MeasureI(digest[63..-1..32])}");
                Message($" h2 = {MeasureI(digest[95..-1..64])}");
                Message($" h3 = {MeasureI(digest[127..-1..96])}");
                Message($" h4 = {MeasureI(digest[159..-1..128])}");
            }
        }

        adjoint (...) {
            mutable a = workspace[ 31 .. -1 ..  0];
            mutable b = workspace[ 63 .. -1 .. 32];
            mutable c = workspace[ 95 .. -1 .. 64];
            mutable d = workspace[127 .. -1 .. 96];
            mutable e = workspace[159 .. -1 ..128];
            mutable temp = new Qubit[0];

            using (extension = Qubit[2048]) {
                let words = ArrayAsWords(32, chunk + extension);
                ExtendWords(words);

                if (DEBUG()) {
                    Message("");
                    Message(" --- PROCESSING CHUNK (adjoint) ---");
                    Message("");
                    Message("Words:");
                    for (i in 0 .. Length(words) - 1) {
                        Message($" words[{i}] = {MeasureI(Reversed(words[i]))}");
                    }
                    Message("");
                    Message("Digest state:");
                    Message($" h0 = {MeasureI(digest[31..-1..0])}");
                    Message($" h1 = {MeasureI(digest[63..-1..32])}");
                    Message($" h2 = {MeasureI(digest[95..-1..64])}");
                    Message($" h3 = {MeasureI(digest[127..-1..96])}");
                    Message($" h4 = {MeasureI(digest[159..-1..128])}");
                    Message("");
                    Message("Rounds:");
                    Message(
                        $" [final] a={MeasureI(a)} b={MeasureI(b)}" +
                        $" c={MeasureI(c)} d={MeasureI(d)} e={MeasureI(e)}"
                    );
                }

                Adjoint Add(a, digest[ 31 .. -1 ..  0]);
                Adjoint Add(b, digest[ 63 .. -1 .. 32]);
                Adjoint Add(c, digest[ 95 .. -1 .. 64]);
                Adjoint Add(d, digest[127 .. -1 .. 96]);
                Adjoint Add(e, digest[159 .. -1 ..128]);

                for (i in 79 .. -1 .. 0) {
                    set temp = a;
                    set a = b;
                    set b = LeftRotate(c, 30);
                    set c = d;
                    set d = e;

                    Adjoint Add(RightRotate(a, 5), temp);
                    set e = temp;

                    Adjoint ComputeRound(i, words, b, c, d, e);

                    if (DEBUG()) {
                        Message(
                            $" [i = {i}] a={MeasureI(a)} b={MeasureI(b)}" +
                            $" c={MeasureI(c)} d={MeasureI(d)} e={MeasureI(e)}"
                        );
                    }
                }

                Adjoint ExtendWords(words);
            }

            Adjoint Xor(digest, workspace);
        }
    }

    /// # Summary
    /// Extends message schedule array for the SHA-1 algorithm.
    ///
    /// # Input
    /// ## words
    /// Array of 60 32-qubit words, with the first 16 derived from the current
    /// chunk.
    operation ExtendWords (words : Qubit[][]) : Unit is Adj {
        body (...) {
            for (i in 16 .. 79) {
                Xor(LeftRotate(words[i -  3], 1), words[i]);
                Xor(LeftRotate(words[i -  8], 1), words[i]);
                Xor(LeftRotate(words[i - 14], 1), words[i]);
                Xor(LeftRotate(words[i - 16], 1), words[i]);
            }
        }

        adjoint invert;
    }

    /// # Summary
    /// Computes a round of the SHA-1 algorithm. Performed in-place, such that
    /// `e` contains `f + e + k + w[i]` after the operation.
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
        b : Qubit[],
        c : Qubit[],
        d : Qubit[],
        e : Qubit[]
    ) : Unit is Adj {
        if (i < 20) {
            // e += Choice(b, c, d) + 0x5A827999
            Choice(b, c, d);
            Add(d, e);
            Adjoint Choice(b, c, d);
            AddConstantNoPhase(0x5A827999, e);
        }
        elif (i < 40) {
            // e += (b xor c xor d) + 0x6ED9EBA1
            Xor(b, d);
            Xor(c, d);
            Add(d, e);
            Adjoint Xor(b, d);
            Adjoint Xor(c, d);
            AddConstantNoPhase(0x6ED9EBA1, e);
        }
        elif (i < 60) {
            // e += Majority(b, c, d) + 0x8F1BBCDC
            Majority(b, c, d);
            Add(d, e);
            Adjoint Majority(b, c, d);
            AddConstantNoPhase(0x8F1BBCDC, e);
        }
        else {
            // e += (b xor c xor d) + 0xCA62C1D6
            Xor(b, d);
            Xor(c, d);
            Add(d, e);
            Adjoint Xor(b, d);
            Adjoint Xor(c, d);
            AddConstantNoPhase(0xCA62C1D6, e);
        }

        // Reverse big-endian word before adding
        Add(Reversed(words[i]), e);
    }
}
