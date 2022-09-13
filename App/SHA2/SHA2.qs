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

namespace Quicc.SHA2 {

    open Microsoft.Quantum.Arrays;
    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Convert;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Common;


    // DEBUG must return false for full simulation compatibility.
    function DEBUG () : Bool { return false; }

    /// # Summary
    /// Represents the 32-bit `k` array in SHA-2.
    /// 
    /// # Input
    /// ## i
    /// Index into the `k` array.
    /// 
    /// # Output
    /// The value of `k[i]` as a big integer.
    function _const_32 (i : Int) : BigInt {
        let k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];
        return IntAsBigInt(k[i]);
    }

    /// # Summary
    /// Represents the 64-bit `k` array in SHA-2.
    /// 
    /// # Input
    /// ## i
    /// Index into the `k` array.
    /// 
    /// # Output
    /// The value of `k[i]` as a big integer.
    function _const_64 (i : Int) : BigInt {
        let k = [
            0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538,
            0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 
            0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2, 0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 
            0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 
            0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5, 0x983e5152, 0xee66dfab, 
            0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 
            0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 
            0x53380d13, 0x9d95b3df, 0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b, 
            0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218, 
            0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8, 0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 
            0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 
            0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec, 
            0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b, 0xca273ece, 0xea26619c, 
            0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178, 0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 
            0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b, 0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 
            0x431d67c4, 0x9c100d4c, 0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
        ];
        return (IntAsBigInt(k[2*i]) <<< 32) + IntAsBigInt(k[2*i + 1]);
    }

    /// # Summary
    /// Returns the appropriate SHA-2 operations and functions based on the
    /// word length.
    /// 
    /// # Input
    /// ## wordLength
    /// Length of a word; 32 or 64 is allowed.
    /// 
    /// # Output
    /// Tuple containing (in order):
    /// - Message schedule extension operation
    /// - Round computation operation
    /// - Function that maps an index to a round constant
    function HandleWordLength (wordLength : Int) : (
        (Qubit[][] => Unit is Adj),
        ((BigInt, Qubit[], Qubit[], Qubit[], Qubit[], Qubit[], Qubit[],
          Qubit[], Qubit[], Qubit[]) => Unit is Adj),
        (Int -> BigInt)
    ) {
        if (wordLength == 32) {
            return (
                ExtendWords(_ext0_32, _ext1_32, _),
                ComputeRound(_sig0_32, _sig1_32, _, _, _, _, _, _, _, _, _, _),
                _const_32
            );
        }
        elif (wordLength == 64) {
            return (
                ExtendWords(_ext0_64, _ext1_64, _),
                ComputeRound(_sig0_64, _sig1_64, _, _, _, _, _, _, _, _, _, _),
                _const_64
            );
        }
        else {
            fail "Invalid word length";
        }
    }

    /// # Summary
    /// Computes the SHA-2 digest of a qubit register encoding bytes in big-
    /// endian format. It is not recommended to invoke this operation directly.
    /// Instead, use convenience operations such as Quicc.SHA2.SHA256.
    /// 
    /// # Input
    /// ## initValues
    /// Array of 32-bit integers to initialize the digest with.
    /// 
    /// ## input
    /// Input message to the SHA-2 algorithm in big-endian format.
    /// 
    /// ## digest
    /// Qubit register to store the output of the SHA-2 algorithm. Length
    /// should be equal to 8 words. For example, if a word is 32-qubits, the
    /// length of `digest` should be 256.
    /// 
    /// ## workspace
    /// Qubit register to save the intermediate result of each chunk. Use
    /// `Quicc.Common.WorkspaceRequirement` to determine the appropriate
    /// length.
    /// 
    /// # References
    /// - Wikipedia:
    ///     https://en.wikipedia.org/wiki/SHA-2
    /// - FIPS 180-4:
    ///     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    /// - Pure python implementation of SHA-2:
    ///     https://github.com/thomdixon/pysha2
    /// - Online hash calculator:
    ///     https://emn178.github.io/online-tools/
    operation SHA2 (
        initValues : Int[],
        input : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        let inputLength = Length(input);
        let digestLength = Length(digest);
        let chunkLength = digestLength*2;
        let encodeLength = digestLength/2;
        let padLength = MessagePadLength(inputLength, chunkLength,
                                         encodeLength);

        InitializeDigest(initValues, digest);

        using (appendix = Qubit[padLength]) {
            PadMessageBE(inputLength, encodeLength, appendix);
            let message = input + appendix;

            for (i in 0 .. Length(message)/chunkLength - 1) {
                ProcessChunk(
                    message[i*chunkLength .. (i + 1)*chunkLength - 1],
                    digest,
                    workspace[i*digestLength .. (i + 1)*digestLength - 1]
                );
            }

            Adjoint PadMessageBE(inputLength, encodeLength, appendix);
        }
    }

    /// # Summary
    /// Initializes SHA-2 digest register.
    /// 
    /// # Input
    /// ## initValues
    /// Array of 32-bit integers to initialize digest with.
    /// 
    /// ## digest
    /// Qubit register of length `32*Length(initValues)`
    operation InitializeDigest (
        initValues : Int[],
        digest : Qubit[]
    ) : Unit is Adj + Ctl {
        for (i in 0 .. Length(initValues) - 1) {
            LoadIBE(initValues[i], digest[i*32 .. i*32 + 31]);
        }
    }

    /// # Summary
    /// Processes a single chunk in the SHA-2 algorithm. Measures and prints
    /// the contents of the virtual registers on every iteration if `DEBUG`
    /// returns `true`.
    /// 
    /// # Input
    /// ## chunk
    /// 512- or 1024-qubit chunk of SHA-2 message to process.
    /// 
    /// ## digest
    /// 256- or 512-qubit register containing the state of the SHA-1 digest.
    /// 
    /// ## workspace
    /// 256- or 512-qubit register used to perform the computations.
    /// 
    /// # Remarks
    /// This operation implements a custom adjoint functor.
    operation ProcessChunk (
        chunk : Qubit[],
        digest : Qubit[],
        workspace : Qubit[]
    ) : Unit is Adj {
        body (...) {
            // wl stands for "word length"
            let wl = Length(digest) / 8;
            let (_extend_words, _compute_round, _const) = HandleWordLength(wl);

            Xor(digest, workspace);

            mutable a = workspace[wl*1 - 1 .. -1 .. wl*0];
            mutable b = workspace[wl*2 - 1 .. -1 .. wl*1];
            mutable c = workspace[wl*3 - 1 .. -1 .. wl*2];
            mutable d = workspace[wl*4 - 1 .. -1 .. wl*3];
            mutable e = workspace[wl*5 - 1 .. -1 .. wl*4];
            mutable f = workspace[wl*6 - 1 .. -1 .. wl*5];
            mutable g = workspace[wl*7 - 1 .. -1 .. wl*6];
            mutable h = workspace[wl*8 - 1 .. -1 .. wl*7];
            mutable temp = new Qubit[0];

            using (extension = Qubit[wl == 32 ? 1536 | 4096]) {
                let words = ArrayAsWords(wl, chunk + extension);
                _extend_words(words);

                if (DEBUG()) {
                    Message("");
                    Message(" --- PROCESSING CHUNK ---");
                    Message("");
                    Message("Words:");
                    for (i in 0 .. Length(words) - 1) {
                        Message($" words[{i}] = {MeasureL(Reversed(words[i]))}");
                    }
                    Message("");
                    Message("Rounds:");
                }

                for (i in 0 .. Length(words) - 1) {
                    if (DEBUG()) {
                        Message(
                            $" [i = {i}] a={MeasureL(a)} b={MeasureL(b)}" +
                            $" c={MeasureL(c)} d={MeasureL(d)}" +
                            $" e={MeasureL(e)} f={MeasureL(f)}" +
                            $" g={MeasureL(g)} h={MeasureL(h)}"
                        );
                    }

                    _compute_round(_const(i), words[i], a, b, c, d,
                                   e, f, g, h);

                    set temp = h;
                    set h = g;
                    set g = f;
                    set f = e;
                    set e = d;
                    set d = c;
                    set c = b;
                    set b = a;
                    set a = temp;
                }

                Adjoint _extend_words(words);
            }

            Add(a, digest[wl*1 - 1 .. -1 .. wl*0]);
            Add(b, digest[wl*2 - 1 .. -1 .. wl*1]);
            Add(c, digest[wl*3 - 1 .. -1 .. wl*2]);
            Add(d, digest[wl*4 - 1 .. -1 .. wl*3]);
            Add(e, digest[wl*5 - 1 .. -1 .. wl*4]);
            Add(f, digest[wl*6 - 1 .. -1 .. wl*5]);
            Add(g, digest[wl*7 - 1 .. -1 .. wl*6]);
            Add(h, digest[wl*8 - 1 .. -1 .. wl*7]);

            if (DEBUG()) {
                Message(
                    $" [final] a={MeasureL(a)} b={MeasureL(b)}" +
                    $" c={MeasureL(c)} d={MeasureL(d)} e={MeasureL(e)}" +
                    $" f={MeasureL(f)} g={MeasureL(g)} h={MeasureL(h)}"
                );
                Message("");
                Message("Digest state:");
                Message($" h0 = {MeasureL(digest[wl*1 - 1 .. -1 .. wl*0])}");
                Message($" h1 = {MeasureL(digest[wl*2 - 1 .. -1 .. wl*1])}");
                Message($" h2 = {MeasureL(digest[wl*3 - 1 .. -1 .. wl*2])}");
                Message($" h3 = {MeasureL(digest[wl*4 - 1 .. -1 .. wl*3])}");
                Message($" h4 = {MeasureL(digest[wl*5 - 1 .. -1 .. wl*4])}");
                Message($" h5 = {MeasureL(digest[wl*6 - 1 .. -1 .. wl*5])}");
                Message($" h6 = {MeasureL(digest[wl*7 - 1 .. -1 .. wl*6])}");
                Message($" h7 = {MeasureL(digest[wl*8 - 1 .. -1 .. wl*7])}");
            }
        }

        adjoint (...) {
            // wl stands for "word length"
            let wl = Length(digest) / 8;
            let (_extend_words, _compute_round, _const) = HandleWordLength(wl);

            mutable a = workspace[wl*1 - 1 .. -1 .. wl*0];
            mutable b = workspace[wl*2 - 1 .. -1 .. wl*1];
            mutable c = workspace[wl*3 - 1 .. -1 .. wl*2];
            mutable d = workspace[wl*4 - 1 .. -1 .. wl*3];
            mutable e = workspace[wl*5 - 1 .. -1 .. wl*4];
            mutable f = workspace[wl*6 - 1 .. -1 .. wl*5];
            mutable g = workspace[wl*7 - 1 .. -1 .. wl*6];
            mutable h = workspace[wl*8 - 1 .. -1 .. wl*7];
            mutable temp = new Qubit[0];

            using (extension = Qubit[wl == 32 ? 1536 | 4096]) {
                let words = ArrayAsWords(wl, chunk + extension);
                _extend_words(words);

                if (DEBUG()) {
                    Message("");
                    Message(" --- PROCESSING CHUNK (adjoint) ---");
                    Message("");
                    Message("Words:");
                    for (i in 0 .. Length(words) - 1) {
                        Message($" words[{i}] = {MeasureL(Reversed(words[i]))}");
                    }
                    Message("");
                    Message("Digest state:");
                    Message($" h0 = {MeasureL(digest[wl*1 - 1 .. -1 .. wl*0])}");
                    Message($" h1 = {MeasureL(digest[wl*2 - 1 .. -1 .. wl*1])}");
                    Message($" h2 = {MeasureL(digest[wl*3 - 1 .. -1 .. wl*2])}");
                    Message($" h3 = {MeasureL(digest[wl*4 - 1 .. -1 .. wl*3])}");
                    Message($" h4 = {MeasureL(digest[wl*5 - 1 .. -1 .. wl*4])}");
                    Message($" h5 = {MeasureL(digest[wl*6 - 1 .. -1 .. wl*5])}");
                    Message($" h6 = {MeasureL(digest[wl*7 - 1 .. -1 .. wl*6])}");
                    Message($" h7 = {MeasureL(digest[wl*8 - 1 .. -1 .. wl*7])}");
                    Message("");
                    Message("Rounds:");
                    Message(
                        $" [final] a={MeasureL(a)} b={MeasureL(b)}" +
                        $" c={MeasureL(c)} d={MeasureL(d)} e={MeasureL(e)}" +
                        $" f={MeasureL(f)} g={MeasureL(g)} h={MeasureL(h)}"
                    );
                }

                Adjoint Add(a, digest[wl*1 - 1 .. -1 .. wl*0]);
                Adjoint Add(b, digest[wl*2 - 1 .. -1 .. wl*1]);
                Adjoint Add(c, digest[wl*3 - 1 .. -1 .. wl*2]);
                Adjoint Add(d, digest[wl*4 - 1 .. -1 .. wl*3]);
                Adjoint Add(e, digest[wl*5 - 1 .. -1 .. wl*4]);
                Adjoint Add(f, digest[wl*6 - 1 .. -1 .. wl*5]);
                Adjoint Add(g, digest[wl*7 - 1 .. -1 .. wl*6]);
                Adjoint Add(h, digest[wl*8 - 1 .. -1 .. wl*7]);

                for (i in Length(words) - 1 .. -1 .. 0) {
                    set temp = a;
                    set a = b;
                    set b = c;
                    set c = d;
                    set d = e;
                    set e = f;
                    set f = g;
                    set g = h;
                    set h = temp;

                    Adjoint _compute_round(_const(i), words[i], a, b, c, d,
                                           e, f, g, h);

                    if (DEBUG()) {
                        Message(
                            $" [i = {i}] a={MeasureL(a)} b={MeasureL(b)}" +
                            $" c={MeasureL(c)} d={MeasureL(d)}" +
                            $" e={MeasureL(e)} f={MeasureL(f)}" +
                            $" g={MeasureL(g)} h={MeasureL(h)}"
                        );
                    }
                }

                Adjoint _extend_words(words);
            }

            Adjoint Xor(digest, workspace);
        }
    }

    /// # Summary
    /// Extends message schedule array for SHA-2.
    /// 
    /// # Input
    /// ## ExtensionOp0
    /// Operation supporting adjoint functor that performs `s0`.
    /// 
    /// ## ExtensionOp1
    /// Operation supporting adjoint functor that performs `s1`.
    /// 
    /// ## words
    /// Array of qubit words, with first 16 derived from the current chunk.
    operation ExtendWords (
        ExtensionOp0 : ((Qubit[], Qubit[]) => Unit is Adj),
        ExtensionOp1 : ((Qubit[], Qubit[]) => Unit is Adj),
        words : Qubit[][]
    ) : Unit is Adj {
        body (...) {
            for (i in 16 .. Length(words) - 1) {
                ExtensionOp0(words[i - 15], words[i]);
                AddBE(words[i - 16], words[i]);
                AddBE(words[i - 7], words[i]);
                using (temp = Qubit[Length(words[0])]) {
                    ExtensionOp1(words[i - 2], temp);
                    AddBE(temp, words[i]);
                    Adjoint ExtensionOp1(words[i - 2], temp);
                }
            }
        }

        adjoint invert;
    }

    /// # Summary
    /// Computes a round of SHA-2. Performed in-place, such that `d` contains
    /// `d + h + Sigma1(e) + Choice(e, f, g) + k[i] + w[i]` and `h` contains
    /// the new value of `d` plus `S0 + Majority(a, b, c)` after the operation.
    /// 
    /// # Input
    /// ## Sigma0
    /// Operation supporting adjoint functor that performs `S0`.
    /// 
    /// ## Sigma1
    /// Operation supporting adjoint functor that performs `S1`.
    /// 
    /// ## roundConstant
    /// Integer representing `k[i]`
    /// 
    /// ## messageScheduleWord
    /// Qubit register representing `w[i]`
    /// 
    /// ## a
    /// Virtual register a
    /// 
    /// ## b
    /// Virtual register b
    /// 
    /// ## c
    /// Virtual register c
    /// 
    /// ## d
    /// Virtual register d
    /// 
    /// ## e
    /// Virtual register e
    /// 
    /// ## f
    /// Virtual register f
    /// 
    /// ## g
    /// Virtual register g
    /// 
    /// ## h
    /// Virtual register h
    operation ComputeRound (
        Sigma0 : ((Qubit[], Qubit[]) => Unit is Adj),
        Sigma1 : ((Qubit[], Qubit[]) => Unit is Adj),
        roundConstant : BigInt,
        messageScheduleWord : Qubit[],
        a : Qubit[],
        b : Qubit[],
        c : Qubit[],
        d : Qubit[],
        e : Qubit[],
        f : Qubit[],
        g : Qubit[],
        h : Qubit[]
    ) : Unit is Adj {
        using (temp = Qubit[Length(a)]) {
            Sigma1(e, temp);
            Add(temp, h);
            Adjoint Sigma1(e, temp);
        }

        Choice(e, f, g);
        Add(g, h);
        Adjoint Choice(e, f, g);

        // Reverse big-endian word before adding
        Add(Reversed(messageScheduleWord), h);

        AddConstantNoPhaseL(roundConstant, h);

        Add(h, d);

        using (temp = Qubit[Length(a)]) {
            Sigma0(a, temp);
            Add(temp, h);
            Adjoint Sigma0(a, temp);
        }

        Majority(a, b, c);
        Add(c, h);
        Adjoint Majority(a, b, c);
    }

    /// # Summary
    /// Performs the `s0` operation for SHA-2 message schedule extension with
    /// 32-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 32-qubit input register.
    /// 
    /// ## output
    /// 32-qubit output register.
    operation _ext0_32 (input : Qubit[], output : Qubit[]) : Unit is Adj {
        body (...) {
            Xor(RightRotate(input, 7), output);
            Xor(RightRotate(input, 18), output);
            Xor(input[0 .. 28], output[3 .. 31]);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the `s1` operation for SHA-2 message schedule extension with
    /// 32-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 32-qubit input register.
    /// 
    /// ## output
    /// 32-qubit output register.
    operation _ext1_32 (input : Qubit[], output : Qubit[]) : Unit is Adj {
        body (...) {
            Xor(RightRotate(input, 17), output);
            Xor(RightRotate(input, 19), output);
            Xor(input[0 .. 21], output[10 .. 31]);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the `s0` operation for SHA-2 message schedule extension with
    /// 64-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 64-qubit input register.
    /// 
    /// ## output
    /// 64-qubit output register.
    operation _ext0_64 (input : Qubit[], output : Qubit[]) : Unit is Adj {
        body (...) {
            Xor(RightRotate(input, 1), output);
            Xor(RightRotate(input, 8), output);
            Xor(input[0 .. 56], output[7 .. 63]);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the `s0` operation for SHA-2 message schedule extension with
    /// 64-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 64-qubit input register.
    /// 
    /// ## output
    /// 64-qubit output register.
    operation _ext1_64 (input : Qubit[], output : Qubit[]) : Unit is Adj {
        body (...) {
            Xor(RightRotate(input, 19), output);
            Xor(RightRotate(input, 61), output);
            Xor(input[0 .. 57], output[6 .. 63]);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the S0 operation in a SHA-2 round with 32-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 32-qubit input register.
    /// 
    /// ## output
    /// 32-qubit output register.
    operation _sig0_32 (input: Qubit[], output: Qubit[]) : Unit is Adj {
        body (...) {
            Xor(LeftRotate(input, 2), output);
            Xor(LeftRotate(input, 13), output);
            Xor(LeftRotate(input, 22), output);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the S1 operation in a SHA-2 round with 32-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 32-qubit input register.
    /// 
    /// ## output
    /// 32-qubit output register.
    operation _sig1_32 (input: Qubit[], output: Qubit[]) : Unit is Adj {
        body (...) {
            Xor(LeftRotate(input, 6), output);
            Xor(LeftRotate(input, 11), output);
            Xor(LeftRotate(input, 25), output);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the S0 operation in a SHA-2 round with 64-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 64-qubit input register.
    /// 
    /// ## output
    /// 64-qubit output register.
    operation _sig0_64 (input: Qubit[], output: Qubit[]) : Unit is Adj
    {
        body (...)
        {
            Xor(LeftRotate(input, 28), output);
            Xor(LeftRotate(input, 34), output);
            Xor(LeftRotate(input, 39), output);
        }
        adjoint self;
    }

    /// # Summary
    /// Performs the S1 operation in a SHA-2 round with 64-qubit words.
    /// 
    /// # Input
    /// ## input
    /// 64-qubit input register.
    /// 
    /// ## output
    /// 64-qubit output register.
    operation _sig1_64 (input: Qubit[], output: Qubit[]) : Unit is Adj
    {
        body (...)
        {
            Xor(LeftRotate(input, 14), output);
            Xor(LeftRotate(input, 18), output);
            Xor(LeftRotate(input, 41), output);
        }
        adjoint self;
    }
}
