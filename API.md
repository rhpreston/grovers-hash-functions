# QuICC API Documentation

Copyright 2022 The MITRE Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Table of Contents
- [Quicc](#quicc)
  - [SearchCRC16](#quiccsearchcrc16)
  - [SearchCRC32](#quiccsearchcrc32)
  - [SearchCRC8](#quiccsearchcrc8)
  - [SearchMD5](#quiccsearchmd5)
  - [SearchSHA1](#quiccsearchsha1)
  - [SearchSHA224](#quiccsearchsha224)
  - [SearchSHA256](#quiccsearchsha256)
  - [SearchSHA384](#quiccsearchsha384)
  - [SearchSHA3_224](#quiccsearchsha3_224)
  - [SearchSHA3_256](#quiccsearchsha3_256)
  - [SearchSHA3_384](#quiccsearchsha3_384)
  - [SearchSHA3_512](#quiccsearchsha3_512)
  - [SearchSHA512](#quiccsearchsha512)
  - [SearchSHA512_224](#quiccsearchsha512_224)
  - [SearchSHA512_256](#quiccsearchsha512_256)
  - [SearchSHAKE128](#quiccsearchshake128)
  - [SearchSHAKE256](#quiccsearchshake256)
- [Quicc.CRC](#quicccrc)
  - [CRC](#quicccrccrc)
  - [CRC16](#quicccrccrc16)
  - [CRC32](#quicccrccrc32)
  - [CRC8](#quicccrccrc8)
- [Quicc.Common](#quicccommon)
  - [Add](#quicccommonadd)
  - [AddBE](#quicccommonaddbe)
  - [AddConstantNoPhase](#quicccommonaddconstantnophase)
  - [AddConstantNoPhaseL](#quicccommonaddconstantnophasel)
  - [And](#quicccommonand)
  - [ArrayAsWords<'T>](#quicccommonarrayaswordst)
  - [Choice](#quicccommonchoice)
  - [LeftRotate<'T>](#quicccommonleftrotatet)
  - [LoadBoolArray](#quicccommonloadboolarray)
  - [LoadI](#quicccommonloadi)
  - [LoadIBE](#quicccommonloadibe)
  - [LoadL](#quicccommonloadl)
  - [LoadLBE](#quicccommonloadlbe)
  - [Majority](#quicccommonmajority)
  - [MeasureBoolArray](#quicccommonmeasureboolarray)
  - [MeasureByteArray](#quicccommonmeasurebytearray)
  - [MeasureByteArrayBE](#quicccommonmeasurebytearraybe)
  - [MeasureI](#quicccommonmeasurei)
  - [MeasureIBE](#quicccommonmeasureibe)
  - [MeasureL](#quicccommonmeasurel)
  - [MeasureLBE](#quicccommonmeasurelbe)
  - [MessagePadLength](#quicccommonmessagepadlength)
  - [Nor](#quicccommonnor)
  - [Not](#quicccommonnot)
  - [Or](#quicccommonor)
  - [PadMessage](#quicccommonpadmessage)
  - [PadMessageBE](#quicccommonpadmessagebe)
  - [ReversedBytes<'T>](#quicccommonreversedbytest)
  - [RightRotate<'T>](#quicccommonrightrotatet)
  - [WorkspaceRequirement](#quicccommonworkspacerequirement)
  - [Xor](#quicccommonxor)
- [Quicc.MD5](#quiccmd5)
  - [ChunkIndex](#quiccmd5chunkindex)
  - [ComputeRound](#quiccmd5computeround)
  - [InitializeDigest](#quiccmd5initializedigest)
  - [MD5](#quiccmd5md5)
  - [MD5WorkspaceRequirement](#quiccmd5md5workspacerequirement)
  - [ProcessChunk](#quiccmd5processchunk)
  - [ShiftAmount](#quiccmd5shiftamount)
  - [SineInt](#quiccmd5sineint)
- [Quicc.SHA1](#quiccsha1)
  - [ComputeRound](#quiccsha1computeround)
  - [ExtendWords](#quiccsha1extendwords)
  - [InitializeDigest](#quiccsha1initializedigest)
  - [ProcessChunk](#quiccsha1processchunk)
  - [SHA1](#quiccsha1sha1)
  - [SHA1WorkspaceRequirement](#quiccsha1sha1workspacerequirement)
- [Quicc.SHA2](#quiccsha2)
  - [ComputeRound](#quiccsha2computeround)
  - [ExtendWords](#quiccsha2extendwords)
  - [HandleWordLength](#quiccsha2handlewordlength)
  - [InitializeDigest](#quiccsha2initializedigest)
  - [ProcessChunk](#quiccsha2processchunk)
  - [SHA2](#quiccsha2sha2)
  - [SHA224](#quiccsha2sha224)
  - [SHA224WorkspaceRequirement](#quiccsha2sha224workspacerequirement)
  - [SHA256](#quiccsha2sha256)
  - [SHA256WorkspaceRequirement](#quiccsha2sha256workspacerequirement)
  - [SHA384](#quiccsha2sha384)
  - [SHA384WorkspaceRequirement](#quiccsha2sha384workspacerequirement)
  - [SHA512](#quiccsha2sha512)
  - [SHA512WorkspaceRequirement](#quiccsha2sha512workspacerequirement)
  - [SHA512_224](#quiccsha2sha512_224)
  - [SHA512_224WorkspaceRequirement](#quiccsha2sha512_224workspacerequirement)
  - [SHA512_256](#quiccsha2sha512_256)
  - [SHA512_256WorkspaceRequirement](#quiccsha2sha512_256workspacerequirement)
  - [_const_32](#quiccsha2_const_32)
  - [_const_64](#quiccsha2_const_64)
  - [_ext0_32](#quiccsha2_ext0_32)
  - [_ext0_64](#quiccsha2_ext0_64)
  - [_ext1_32](#quiccsha2_ext1_32)
  - [_ext1_64](#quiccsha2_ext1_64)
  - [_sig0_32](#quiccsha2_sig0_32)
  - [_sig0_64](#quiccsha2_sig0_64)
  - [_sig1_32](#quiccsha2_sig1_32)
  - [_sig1_64](#quiccsha2_sig1_64)
- [Quicc.SHA3](#quiccsha3)
  - [AdjointKeccakF1600](#quiccsha3adjointkeccakf1600)
  - [Chi](#quiccsha3chi)
  - [Iota](#quiccsha3iota)
  - [Keccak](#quiccsha3keccak)
  - [KeccakF1600](#quiccsha3keccakf1600)
  - [LanesAsString<'T>](#quiccsha3lanesasstringt)
  - [PrintLanes](#quiccsha3printlanes)
  - [ReverseRhoPi<'T>](#quiccsha3reverserhopit)
  - [RhoPi<'T>](#quiccsha3rhopit)
  - [SHA3_224](#quiccsha3sha3_224)
  - [SHA3_256](#quiccsha3sha3_256)
  - [SHA3_384](#quiccsha3sha3_384)
  - [SHA3_512](#quiccsha3sha3_512)
  - [SHAKE128](#quiccsha3shake128)
  - [SHAKE256](#quiccsha3shake256)
  - [StringAsLanes<'T>](#quiccsha3stringaslanest)
  - [Theta](#quiccsha3theta)
- [Quicc.Search](#quiccsearch)
  - [CheckSearchResult](#quiccsearchchecksearchresult)
  - [NumIterations](#quiccsearchnumiterations)
  - [OpAsOracle](#quiccsearchopasoracle)
  - [PerformSearchOnOp](#quiccsearchperformsearchonop)
  - [RunGroverOnOracle](#quiccsearchrungroveronoracle)

## Quicc

### Quicc.SearchCRC16

```
operation SearchCRC16 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Attempts to reverse CRC16 with Grover's algorithm.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchCRC32

```
operation SearchCRC32 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Attempts to reverse CRC32 with Grover's algorithm.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchCRC8

```
operation SearchCRC8 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Attempts to reverse CRC8 with Grover's algorithm.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchMD5

```
operation SearchMD5 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against MD5. That is, attempts to find a
message with specified length whose MD5 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA1

```
operation SearchSHA1 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-1. That is, attempts to find a
message with specified length whose SHA-1 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA224

```
operation SearchSHA224 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-224. That is, attempts to find a
message with specified length whose SHA-224 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA256

```
operation SearchSHA256 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-256. That is, attempts to find a
message with specified length whose SHA-256 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA384

```
operation SearchSHA384 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-348. That is, attempts to find a
message with specified length whose SHA-348 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA3_224

```
operation SearchSHA3_224 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA3-224. That is, attempts to find
a message with specified length whose SHA3-224 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA3_256

```
operation SearchSHA3_256 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA3-256. That is, attempts to find
a message with specified length whose SHA3-256 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA3_384

```
operation SearchSHA3_384 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA3-384. That is, attempts to find
a message with specified length whose SHA3-384 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA3_512

```
operation SearchSHA3_512 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA3-512. That is, attempts to find
a message with specified length whose SHA3-512 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA512

```
operation SearchSHA512 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-512. That is, attempts to find a
message with specified length whose SHA-512 digest is some given value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA512_224

```
operation SearchSHA512_224 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-512/224. That is, attempts to
find a message with specified length whose SHA-512 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHA512_256

```
operation SearchSHA512_256 ( numSearchTargets : Int[], inputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHA-512/256. That is, attempts to
find a message with specified length whose SHA-512 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHAKE128

```
operation SearchSHAKE128 ( numSearchTargets : Int[], inputLength : Int, outputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHAKE128. That is, attempts to find
a message with specified length whose SHAKE128 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputLength
Number of qubits in SHAKE128 output.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.SearchSHAKE256

```
operation SearchSHAKE256 ( numSearchTargets : Int[], inputLength : Int, outputLength : Int, outputToMatch : BigInt ) : BigInt
```

#### Summary
Conducts a preimage attack against SHAKE256. That is, attempts to find
a message with specified length whose SHAKE256 digest is some given
value.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. It's recommended to use a predefined
search strategy to generate this parameter.

##### inputLength
Number of qubits in input message we are looking for.

##### outputLength
Number of qubits in SHAKE128 output.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

## Quicc.CRC

### Quicc.CRC.CRC

```
operation CRC ( width : Int, poly : Int, init : Int, input : Qubit[], output : Qubit[] ) : Unit is Adj
```

#### Summary
Computes the cyclic redundancy check (CRC) of a qubit register.
Logically identical to a classical implementation, except that the
REFIN, REFOUT, and XOROUT parameters are handled outside the operation.
It is not recommended to invoke this operation directly. Instead, use
convenience operations such as Quicc.CRC.CRC8.

#### Input
##### width
Width of CRC algorithm in bits. This is bit-length of the polynomial
minus 1.

##### poly
CRC polynomial expressed as an integer with MSB omitted.

##### init
Value to XOR with the first `width` qubits of the input message.

##### input
Qubit register containing the input message in big-endian format.

##### output
Qubit register to contain output checksum after the operation.

#### Remarks
This is a toy example. CRC is not meant for cryptography and is easily
reversible on a classical computer. Note also that this operation is
performed more efficiently on a classical computer using a precomputed
table.

#### References
- Wikipedia:
https://en.wikipedia.org/wiki/Cyclic_redundancy_check
- A Painless Guide to CRC Error Detection Algorithms:
https://zlib.net/crc_v3.txt
- Online CRC Calculator:
https://crccalc.com/

---

### Quicc.CRC.CRC16

```
operation CRC16 ( input : Qubit[], output : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of CRC-16 (a.k.a. CRC-16-IBM,
CRC-16/ARC).

#### Input
##### input
Qubit register containing input message.

##### output
Qubit register to contain output checksum after the operation.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.CRC.CRC32

```
operation CRC32 ( input : Qubit[], output : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of CRC-32.

#### Input
##### input
Qubit register containing input message.

##### output
Qubit register to contain output checksum after the operation.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.CRC.CRC8

```
operation CRC8 ( input : Qubit[], output : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of CRC-8 (a.k.a. CRC-8-CCITT).

#### Input
##### input
Qubit register containing input message.

##### output
Qubit register to contain output checksum after the operation.

##### workspace
Unused qubit register provided for interface consistency.

---

## Quicc.Common

### Quicc.Common.Add

```
operation Add (addend : Qubit[], target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Performs an in-place addition of two qubit registers containing
integers represented in little-endian format.

#### Input
##### addend
Addend register. Not changed by the operation.

##### target
Target register. Contains the sum after the operation.

---

### Quicc.Common.AddBE

```
operation AddBE (addend : Qubit[], target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Performs an in-place addition of two qubit registers containing
integers represented in big-endian format.

#### Input
##### addend
Addend register. Not changed by the operation.

##### target
Target register. Contains the sum after the operation.

---

### Quicc.Common.AddConstantNoPhase

```
operation AddConstantNoPhase ( addend : Int, target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Performs an in-place addition of an integer constant and a qubit
register containing an integer represented in little-endian format.

#### Input
##### addend
Number to increment `target`.

##### target
Target register. Contains the sum after the operation.

#### Remarks
More efficient arithmetic adders exist that utilize phase operations,
but these are incompatible with the Toffoli simulator.

#### See also
- Quicc.Common.AddConstantNoPhaseL

---

### Quicc.Common.AddConstantNoPhaseL

```
operation AddConstantNoPhaseL ( addend : BigInt, target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Performs an in-place addition of a big integer constant and a qubit
register containing an integer represented in little-endian format.

#### Input
##### addend
Number to increment `target`.

##### target
Target register. Contains the sum after the operation.

#### Remarks
More efficient arithmetic adders exist that utilize phase operations,
but these are incompatible with the Toffoli simulator.

#### See also
- Quicc.Common.AddConstantNoPhase

---

### Quicc.Common.And

```
operation And ( control1 : Qubit[], control2 : Qubit[], target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Applies CCNOT to each triple of (control1, control2, target) qubits.

#### Input
##### control1
First control register. Not changed by the operation.

##### control2
Second control register. Not changed by the operation.

##### target
Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
contain (control1 AND control2) after the operation.

---

### Quicc.Common.ArrayAsWords<'T>

```
function ArrayAsWords<'T> ( wordLength : Int, array : 'T[] ) : 'T[][]
```

#### Summary
Breaks up a flat array into an array of words with specified
length.

#### Input
##### wordLength
Number of elements per word.

##### array
Array to break up.

#### Output
Array of arrays.

---

### Quicc.Common.Choice

```
operation Choice ( control : Qubit[], choice1 : Qubit[], choice2 : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Applies in-place bitwise choice operation to 3 qubit registers. If the
control is 1, the first choice is selected; if it is 0, the second
choice.

#### Input
##### control
Control register. Not changed by the operation.

##### choice1
Register containing first choice. Not changed by the operation.

##### choice2
Register containing second choice. For each qubit in `control` that is
a 1, the corresponding qubit will be changed to that in `choice1`.

---

### Quicc.Common.LeftRotate<'T>

```
function LeftRotate<'T> (array : 'T[], amount : Int) : 'T[]
```

#### Summary
Shifts an array to the left in a circular manner by a given amount.
I.e., elements that "fall off" the left are "fed into" the right.

#### Input
##### array
Array to rotate.

##### amount
Amount to rotate by.

#### Type Parameters
##### 'T
Type of array values.

#### Output
Rotated array.

#### See also
- Quicc.App.Common.RightRotate

---

### Quicc.Common.LoadBoolArray

```
operation LoadBoolArray ( value : Bool[], target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Loads a boolean array into a qubit register. Applies X to indices that
contain `true`.

#### Input
##### value
Boolean array to load into register.

##### target
Qubit register to load `value` into.

#### Remarks
Does not fail if `value` and `target` have different lengths.

#### See also
- Quicc.Common.LoadI
- Quicc.Common.LoadIBE
- Quicc.Common.LoadL
- Quicc.Common.LoadLBE

---

### Quicc.Common.LoadI

```
operation LoadI (value : Int, target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Loads an integer into a qubit register in little-endian format. Can
also be used to toggle qubits with a bitmask.

#### Input
##### value
Number to load into register. Must be positive and less than 2^63.

##### target
Qubit register to load `value` into.

#### Remarks
This operation is a wrapper for
Microsoft.Quantum.Arithmetic.ApplyXorInPlace.

#### See also
- Quicc.Common.LoadBoolArray
- Quicc.Common.LoadIBE
- Quicc.Common.LoadL
- Quicc.Common.LoadLBE

---

### Quicc.Common.LoadIBE

```
operation LoadIBE (value : Int, target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Loads an integer into a qubit register in big-endian format. Can
also be used to toggle qubits with a bitmask.

#### Input
##### value
Number to load into register. Must be positive and less than 2^63.

##### target
Qubit register to load `value` into.

#### See also
- Quicc.Common.LoadBoolArray
- Quicc.Common.LoadI
- Quicc.Common.LoadL
- Quicc.Common.LoadLBE

---

### Quicc.Common.LoadL

```
operation LoadL (value : BigInt, target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Loads a big integer into a qubit register in little-endian format. Can
also be used to toggle qubits with a bitmask.

#### Input
##### value
Positive number to load into register.

##### target
Qubit register to load `value` into.

#### Remarks
The operation will not fail if `value` is negative, but the data will
not be interpreted correctly when it is read later.

#### See also
- Quicc.Common.LoadBoolArray
- Quicc.Common.LoadI
- Quicc.Common.LoadIBE
- Quicc.Common.LoadLBE

---

### Quicc.Common.LoadLBE

```
operation LoadLBE (value : BigInt, target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Loads a big integer into a qubit register in big-endian format. Can
also be used to toggle qubits with a bitmask.

#### Input
##### value
Positive number to load into register.

##### target
Qubit register to load `value` into.

#### Remarks
The operation will not fail if `value` is negative, but the data will
not be interpreted correctly when it is read later.

#### See also
- Quicc.Common.LoadBoolArray
- Quicc.Common.LoadI
- Quicc.Common.LoadIBE
- Quicc.Common.LoadL

---

### Quicc.Common.Majority

```
operation Majority ( input1 : Qubit[], input2 : Qubit[], input3 : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Applies in-place bitwise majority operation to 3 qubit registers. If at
least two of the inputs are 1, the output will be 1.

#### Input
##### input1
First input register. Not changed by the operation.

##### input2
Second input register. Not changed by the operation.

##### input3
Third input register. Contains the output after the operation.

---

### Quicc.Common.MeasureBoolArray

```
operation MeasureBoolArray (target: Qubit[]) : Bool[]
```

#### Summary
Measures each qubit in a register and returns the results as a Bool
array, where `One` is mapped to `true` and `Zero` is mapped to `false`.

#### Input
##### target
Qubit register to measure.

#### Output
Bool array containing result of each measurement.

#### See also
- Quicc.Common.MeasureI
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureL
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArray
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MeasureByteArray

```
operation MeasureByteArray (target: Qubit[]) : Int[]
```

#### Summary
Measures each qubit in a register and interprets the result as an array
of bytes with each byte in little-endian format.

#### Input
##### target
Qubit register encoding bytes.

#### Output
Array of integers representing bytes.

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureI
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureL
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MeasureByteArrayBE

```
operation MeasureByteArrayBE (target: Qubit[]) : Int[]
```

#### Summary
Measures each qubit in a register and interprets the result as an array
of bytes with each byte in big-endian format.

#### Input
##### target
Qubit register encoding bytes.

#### Output
Array of integers representing bytes.

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureI
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureL
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArray

---

### Quicc.Common.MeasureI

```
operation MeasureI (target: Qubit[]) : Int
```

#### Summary
Measures each qubit in a register and interprets the result as an
integer in little-endian format.

#### Input
##### target
Qubit register in little-endian format.

#### Output
Unsigned integer containing interpreted result of measurement.

#### Remarks
This operation is distinct from
Microsoft.Quantum.Arithmetic.MeasureInteger in two ways:
- It does not reset the input register to the $\ket{00\cdots 0}$ state
- It relaxes the input type to `Qubit[]`

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureL
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArray
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MeasureIBE

```
operation MeasureIBE (target: Qubit[]) : Int
```

#### Summary
Measures each qubit in a register and interprets the result as an
integer in big-endian format.

#### Input
##### target
Qubit register in big-endian format.

#### Output
Unsigned integer containing interpreted result of measurement.

#### Remarks
This operation does not reset the input register to the
$\ket{00\cdots 0}$ state.

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureI
- Quicc.Common.MeasureL
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArray
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MeasureL

```
operation MeasureL (target: Qubit[]) : BigInt
```

#### Summary
Measures each qubit in a register and interprets the result as a
positive big integer in little-endian format.

#### Input
##### target
Qubit register in little-endian format.

#### Output
Positive big integer containing interpreted result of measurement.

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureI
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureLBE
- Quicc.Common.MeasureByteArray
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MeasureLBE

```
operation MeasureLBE (target: Qubit[]) : BigInt
```

#### Summary
Measures each qubit in a register and interprets the result as a
positive big integer in big-endian format.

#### Input
##### target
Qubit register in big-endian format.

#### Output
Positive big integer containing interpreted result of measurement.

#### See also
- Quicc.Common.MeasureBoolArray
- Quicc.Common.MeasureI
- Quicc.Common.MeasureIBE
- Quicc.Common.MeasureL
- Quicc.Common.MeasureByteArray
- Quicc.Common.MeasureByteArrayBE

---

### Quicc.Common.MessagePadLength

```
function MessagePadLength ( inputLength : Int, chunkLength : Int, encodeLength : Int ) : Int
```

#### Summary
Number of qubits to append to the input message to a hash function.

#### Input
##### inputLength
Qubit-length of input message.

##### chunkLength
Qubit-length of a chunk in the hash function

##### encodeLength
Number of qubits needed to encode the message length.

#### Output
Number of qubits to pad.

#### Remarks
The formula uses modular arithmetic to ensure the result is at least
`encodeLength + 1`, and the total length of the padded message is a
multiple of `chunkLength`.

---

### Quicc.Common.Nor

```
operation Nor ( control1 : Qubit[], control2 : Qubit[], target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Convenience operation implementing bitwise NOR.

#### Input
##### control1
First control register. Not changed by the operation.

##### control2
Second control register. Not changed by the operation.

##### target
Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
contain (control1 NOR control2) after the operation.

---

### Quicc.Common.Not

```
operation Not (target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Applies X to each qubit in the target register.

#### Input
##### target
Register containing target qubits.

---

### Quicc.Common.Or

```
operation Or ( control1 : Qubit[], control2 : Qubit[], target : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Convenience operation implementing bitwise OR.

#### Input
##### control1
First control register. Not changed by the operation.

##### control2
Second control register. Not changed by the operation.

##### target
Target register. If it begins in the $\ket{00\cdots 0}$ state, it will
contain (control1 OR control2) after the operation.

---

### Quicc.Common.PadMessage

```
operation PadMessage ( inputLength : Int, encodeLength : Int, appendix : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Does preprocessing step for hash functions using little-endian
encoding.

#### Input
##### inputLength
Qubit-length of input message.

##### encodeLength
Number of qubits to encode `inputLength` in.

##### appendix
Register containing message pad qubits. Use
Quicc.Common.MessagePadLength to determine the appropriate length.

#### See also
- Quicc.Common.PadMessageBE

---

### Quicc.Common.PadMessageBE

```
operation PadMessageBE ( inputLength : Int, encodeLength : Int, appendix : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Does preprocessing step for hash functions using big-endian encoding.

#### Input
##### inputLength
Qubit-length of input message.

##### encodeLength
Number of qubits to encode `inputLength` in.

##### appendix
Register containing message pad qubits. Use
Quicc.Common.MessagePadLength to determine the appropriate length.

#### See also
- Quicc.Common.PadMessage

---

### Quicc.Common.ReversedBytes<'T>

```
function ReversedBytes<'T> (array : 'T[]) : 'T[]
```

#### Summary
Reverses the order of every 8 elements in the array. This has the
effect of toggling between big- and little-endian byte encoding.

#### Input
##### Array
Array to reverse the byte endianness in.

#### Output
Array with reordering.

---

### Quicc.Common.RightRotate<'T>

```
function RightRotate<'T> (array : 'T[], amount : Int) : 'T[]
```

#### Summary
Shifts an array to the right in a circular manner by a given amount.
I.e., elements that "fall off" the right are "fed into" the left.

#### Input
##### array
Array to rotate.

##### amount
Amount to rotate by.

#### Type Parameters
##### 'T
Type of array values.

#### Output
Rotated array.

#### See also
- Quicc.App.Common.RightRotate

---

### Quicc.Common.WorkspaceRequirement

```
function WorkspaceRequirement ( digestLength : Int, chunkLength : Int, encodeLength : Int, inputLength : Int ) : Int
```

#### Summary
Number of workspace qubits needed to perform the hash function.

#### Input
##### digestLength
Qubit-length of message digest, i.e., number of qubits required per
chunk.

##### chunkLength
Qubit-length of a single chunk.

##### encodeLength
Number of qubits needed to encode the message length.

##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.Common.Xor

```
operation Xor (control : Qubit[], target : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Applies CNOT to each pair of (control, target) qubits.

#### Input
##### control
Register containing control qubits. Not changed by the operation.

##### target
Register containing target qubits. Modified by the operation.

---

## Quicc.MD5

### Quicc.MD5.ChunkIndex

```
function ChunkIndex (i : Int) : Int
```

#### Summary
Returns the appropriate word-index into the current chunk based on the
iterator value. This is the `g` in the MD5 algorithm.

#### Input
##### i
Iterator value.

#### Output
Corresponding `g` value.

---

### Quicc.MD5.ComputeRound

```
operation ComputeRound ( i : Int, words : Qubit[][], a : Qubit[], b : Qubit[], c : Qubit[], d : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Computes a round of the MD5 algorithm. Performed in-place, such that
`a` contains `F + A + K[i] + M[g]` after the operation.

#### Input
##### i
Iterator value.

##### words
Array of 32-qubit words derived from the current chunk.

##### a
32-qubit virtual register.

##### b
32-qubit virtual register.

##### c
32-qubit virtual register.

##### d
32-qubit virtual register.

---

### Quicc.MD5.InitializeDigest

```
operation InitializeDigest (digest : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Initializes MD5 digest register.

#### Input
##### digest
128-qubit register.

---

### Quicc.MD5.MD5

```
operation MD5 ( input : Qubit[], digest : Qubit[], workspace: Qubit[] ) : Unit is Adj
```

#### Summary
Computes the MD5 digest of a qubit register encoding bytes in little-
endian format. Logically identical to a classical implementation.

#### Input
##### input
Input message to MD5 algorithm in big-endian format.

##### digest
128-qubit register to store the output of the MD5 algorithm.

##### workspace
Qubit register to save the intermediate result of each chunk. Use
`Quicc.MD5.MD5WorkspaceRequirement` to determine the appropriate
length.

#### References
- Wikipedia:
https://en.wikipedia.org/wiki/MD5
- RFC 1321:
https://tools.ietf.org/html/rfc1321
- MD5 Hash Generator:
https://www.md5hashgenerator.com/

---

### Quicc.MD5.MD5WorkspaceRequirement

```
function MD5WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed to perform the MD5 algorithm.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.MD5.ProcessChunk

```
operation ProcessChunk ( chunk : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Processes a single 512-bit chunk in the MD5 algorithm. Measures and
prints the contents of the virtual registers on every iteration if
`DEBUG` returns `true`.

#### Input
##### chunk
512-qubit chunk of MD5 message to process.

##### digest
128-qubit register containing the state of the MD5 digest.

##### workspace
128-qubit register used to perform the computations.

#### Remarks
This operation implements a custom adjoint functor.

---

### Quicc.MD5.ShiftAmount

```
function ShiftAmount (i : Int) : Int 
```

#### Summary
Represents the `s` array in the MD5 algorithm.

#### Input
##### i
Index into the `s` array. Must be in [0..63].

#### Output
The value of `s[i]`.

---

### Quicc.MD5.SineInt

```
function SineInt (i : Int) : Int 
```

#### Summary
Returns the integer representation of the sine of `Input`. This is the
`K` array in the MD5 algorithm.

#### Input
##### i
Index into the `K` array. Must be in [0..63].

#### Output
`K[Index]`.

---

## Quicc.SHA1

### Quicc.SHA1.ComputeRound

```
operation ComputeRound ( i : Int, words : Qubit[][], b : Qubit[], c : Qubit[], d : Qubit[], e : Qubit[] ) : Unit is Adj
```

#### Summary
Computes a round of the SHA-1 algorithm. Performed in-place, such that
`e` contains `f + e + k + w[i]` after the operation.

#### Input
##### i
Iterator value.

##### words
Array of 32-qubit words derived from the current chunk.

##### a
32-qubit virtual register.

##### b
32-qubit virtual register.

##### c
32-qubit virtual register.

##### d
32-qubit virtual register.

---

### Quicc.SHA1.ExtendWords

```
operation ExtendWords (words : Qubit[][]) : Unit is Adj
```

#### Summary
Extends message schedule array for the SHA-1 algorithm.

#### Input
##### words
Array of 60 32-qubit words, with the first 16 derived from the current
chunk.

---

### Quicc.SHA1.InitializeDigest

```
operation InitializeDigest (digest : Qubit[]) : Unit is Adj + Ctl
```

#### Summary
Initializes SHA-1 digest register.

#### Input
##### digest
160-qubit register.

---

### Quicc.SHA1.ProcessChunk

```
operation ProcessChunk ( chunk : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Processes a single 512-bit chunk in the SHA-1 algorithm. Measures and
prints the contents of the virtual registers on every iteration if
`DEBUG` returns `true`.

#### Input
##### chunk
512-qubit chunk of SHA-1 message to process.

##### digest
160-qubit register containing the state of the SHA-1 digest.

##### workspace
160-qubit register used to perform the computations.

#### Remarks
This operation implements a custom adjoint functor.

---

### Quicc.SHA1.SHA1

```
operation SHA1 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Computes the SHA-1 digest of a qubit register encoding bytes in little-
endian format. Logically identical to a classical implementation.

#### Input
##### input
Input message to the SHA-1 algorithm in big-endian format.

##### digest
160-qubit register to store the output of the SHA-1 algorithm.

##### workspace
Qubit register to save the intermediate result of each chunk. Use
`Quicc.SHA1.SHA1WorkspaceRequirement` to determine the
appropriate length.

#### References
- Wikipedia:
https://en.wikipedia.org/wiki/SHA-1
- Example Python implementation:
https://github.com/ajalt/python-sha1
- SHA-1 Hash Generator:
http://www.sha1-online.com/

---

### Quicc.SHA1.SHA1WorkspaceRequirement

```
function SHA1WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed to perform the SHA-1 algorithm.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

## Quicc.SHA2

### Quicc.SHA2.ComputeRound

```
operation ComputeRound ( Sigma0 : ((Qubit[], Qubit[]) => Unit is Adj), Sigma1 : ((Qubit[], Qubit[]) => Unit is Adj), roundConstant : BigInt, messageScheduleWord : Qubit[], a : Qubit[], b : Qubit[], c : Qubit[], d : Qubit[], e : Qubit[], f : Qubit[], g : Qubit[], h : Qubit[] ) : Unit is Adj
```

#### Summary
Computes a round of SHA-2. Performed in-place, such that `d` contains
`d + h + Sigma1(e) + Choice(e, f, g) + k[i] + w[i]` and `h` contains
the new value of `d` plus `S0 + Majority(a, b, c)` after the operation.

#### Input
##### Sigma0
Operation supporting adjoint functor that performs `S0`.

##### Sigma1
Operation supporting adjoint functor that performs `S1`.

##### roundConstant
Integer representing `k[i]`

##### messageScheduleWord
Qubit register representing `w[i]`

##### a
Virtual register a

##### b
Virtual register b

##### c
Virtual register c

##### d
Virtual register d

##### e
Virtual register e

##### f
Virtual register f

##### g
Virtual register g

##### h
Virtual register h

---

### Quicc.SHA2.ExtendWords

```
operation ExtendWords ( ExtensionOp0 : ((Qubit[], Qubit[]) => Unit is Adj), ExtensionOp1 : ((Qubit[], Qubit[]) => Unit is Adj), words : Qubit[][] ) : Unit is Adj
```

#### Summary
Extends message schedule array for SHA-2.

#### Input
##### ExtensionOp0
Operation supporting adjoint functor that performs `s0`.

##### ExtensionOp1
Operation supporting adjoint functor that performs `s1`.

##### words
Array of qubit words, with first 16 derived from the current chunk.

---

### Quicc.SHA2.HandleWordLength

```
function HandleWordLength (wordLength : Int) : ( (Qubit[][] => Unit is Adj), ((BigInt, Qubit[], Qubit[], Qubit[], Qubit[], Qubit[], Qubit[], Qubit[], Qubit[], Qubit[]) => Unit is Adj), (Int -> BigInt) )
```

#### Summary
Returns the appropriate SHA-2 operations and functions based on the
word length.

#### Input
##### wordLength
Length of a word; 32 or 64 is allowed.

#### Output
Tuple containing (in order):
- Message schedule extension operation
- Round computation operation
- Function that maps an index to a round constant

---

### Quicc.SHA2.InitializeDigest

```
operation InitializeDigest ( initValues : Int[], digest : Qubit[] ) : Unit is Adj + Ctl
```

#### Summary
Initializes SHA-2 digest register.

#### Input
##### initValues
Array of 32-bit integers to initialize digest with.

##### digest
Qubit register of length `32*Length(initValues)`

---

### Quicc.SHA2.ProcessChunk

```
operation ProcessChunk ( chunk : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Processes a single chunk in the SHA-2 algorithm. Measures and prints
the contents of the virtual registers on every iteration if `DEBUG`
returns `true`.

#### Input
##### chunk
512- or 1024-qubit chunk of SHA-2 message to process.

##### digest
256- or 512-qubit register containing the state of the SHA-1 digest.

##### workspace
256- or 512-qubit register used to perform the computations.

#### Remarks
This operation implements a custom adjoint functor.

---

### Quicc.SHA2.SHA2

```
operation SHA2 ( initValues : Int[], input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Computes the SHA-2 digest of a qubit register encoding bytes in big-
endian format. It is not recommended to invoke this operation directly.
Instead, use convenience operations such as Quicc.SHA2.SHA256.

#### Input
##### initValues
Array of 32-bit integers to initialize the digest with.

##### input
Input message to the SHA-2 algorithm in big-endian format.

##### digest
Qubit register to store the output of the SHA-2 algorithm. Length
should be equal to 8 words. For example, if a word is 32-qubits, the
length of `digest` should be 256.

##### workspace
Qubit register to save the intermediate result of each chunk. Use
`Quicc.Common.WorkspaceRequirement` to determine the appropriate
length.

#### References
- Wikipedia:
https://en.wikipedia.org/wiki/SHA-2
- FIPS 180-4:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
- Pure python implementation of SHA-2:
https://github.com/thomdixon/pysha2
- Online hash calculator:
https://emn178.github.io/online-tools/

---

### Quicc.SHA2.SHA224

```
operation SHA224 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-224

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA224WorkspaceRequirement` to determine the appropriate
length.

---

### Quicc.SHA2.SHA224WorkspaceRequirement

```
function SHA224WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-224.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2.SHA256

```
operation SHA256 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-256.

#### Input
##### input
Input message in big-endian format.

##### digest
256-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA256WorkspaceRequirement` to determine the appropriate
length.

---

### Quicc.SHA2.SHA256WorkspaceRequirement

```
function SHA256WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-256.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2.SHA384

```
operation SHA384 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-384.

#### Input
##### input
Input message in big-endian format.

##### digest
384-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA384WorkspaceRequirement` to determine the appropriate
length.

---

### Quicc.SHA2.SHA384WorkspaceRequirement

```
function SHA384WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-224.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2.SHA512

```
operation SHA512 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-512.

#### Input
##### input
Input message in big-endian format.

##### digest
512-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA512WorkspaceRequirement` to determine the appropriate
length.

---

### Quicc.SHA2.SHA512WorkspaceRequirement

```
function SHA512WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-512.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2.SHA512_224

```
operation SHA512_224 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-512/224.

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA512_224WorkspaceRequirement` to determine the
appropriate length.

---

### Quicc.SHA2.SHA512_224WorkspaceRequirement

```
function SHA512_224WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-512/224.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2.SHA512_256

```
operation SHA512_256 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA-512/256.

#### Input
##### input
Input message in big-endian format.

##### digest
256-qubit register to store the output.

##### workspace
Qubit register required to run the algorithm. Use
`Quicc.SHA2.SHA512_256WorkspaceRequirement` to determine the
appropriate length.

---

### Quicc.SHA2.SHA512_256WorkspaceRequirement

```
function SHA512_256WorkspaceRequirement (inputLength : Int) : Int
```

#### Summary
Number of workspace qubits needed for SHA-512/256.

#### Input
##### inputLength
Qubit-length of input message.

#### Output
Number of workspace qubits required.

---

### Quicc.SHA2._const_32

```
function _const_32 (i : Int) : BigInt
```

#### Summary
Represents the 32-bit `k` array in SHA-2.

#### Input
##### i
Index into the `k` array.

#### Output
The value of `k[i]` as a big integer.

---

### Quicc.SHA2._const_64

```
function _const_64 (i : Int) : BigInt
```

#### Summary
Represents the 64-bit `k` array in SHA-2.

#### Input
##### i
Index into the `k` array.

#### Output
The value of `k[i]` as a big integer.

---

### Quicc.SHA2._ext0_32

```
operation _ext0_32 (input : Qubit[], output : Qubit[]) : Unit is Adj
```

#### Summary
Performs the `s0` operation for SHA-2 message schedule extension with
32-qubit words.

#### Input
##### input
32-qubit input register.

##### output
32-qubit output register.

---

### Quicc.SHA2._ext0_64

```
operation _ext0_64 (input : Qubit[], output : Qubit[]) : Unit is Adj
```

#### Summary
Performs the `s0` operation for SHA-2 message schedule extension with
64-qubit words.

#### Input
##### input
64-qubit input register.

##### output
64-qubit output register.

---

### Quicc.SHA2._ext1_32

```
operation _ext1_32 (input : Qubit[], output : Qubit[]) : Unit is Adj
```

#### Summary
Performs the `s1` operation for SHA-2 message schedule extension with
32-qubit words.

#### Input
##### input
32-qubit input register.

##### output
32-qubit output register.

---

### Quicc.SHA2._ext1_64

```
operation _ext1_64 (input : Qubit[], output : Qubit[]) : Unit is Adj
```

#### Summary
Performs the `s0` operation for SHA-2 message schedule extension with
64-qubit words.

#### Input
##### input
64-qubit input register.

##### output
64-qubit output register.

---

### Quicc.SHA2._sig0_32

```
operation _sig0_32 (input: Qubit[], output: Qubit[]) : Unit is Adj
```

#### Summary
Performs the S0 operation in a SHA-2 round with 32-qubit words.

#### Input
##### input
32-qubit input register.

##### output
32-qubit output register.

---

### Quicc.SHA2._sig0_64

```
operation _sig0_64 (input: Qubit[], output: Qubit[]) : Unit is Adj 
```

#### Summary
Performs the S0 operation in a SHA-2 round with 64-qubit words.

#### Input
##### input
64-qubit input register.

##### output
64-qubit output register.

---

### Quicc.SHA2._sig1_32

```
operation _sig1_32 (input: Qubit[], output: Qubit[]) : Unit is Adj
```

#### Summary
Performs the S1 operation in a SHA-2 round with 32-qubit words.

#### Input
##### input
32-qubit input register.

##### output
32-qubit output register.

---

### Quicc.SHA2._sig1_64

```
operation _sig1_64 (input: Qubit[], output: Qubit[]) : Unit is Adj 
```

#### Summary
Performs the S1 operation in a SHA-2 round with 64-qubit words.

#### Input
##### input
64-qubit input register.

##### output
64-qubit output register.

---

## Quicc.SHA3

### Quicc.SHA3.AdjointKeccakF1600

```
operation AdjointKeccakF1600 (state : Qubit[]) : Qubit[]
```

#### Summary
Performs the inverse Keccak-f[1600] permutation.

#### Input
##### state
1600-qubit array containing the state of the Keccak permutation.

#### Output
Modified state array.

#### See also
Quicc.SHA3.KeccakF1600

---

### Quicc.SHA3.Chi

```
operation Chi (lanes : Qubit[][][]) : Unit is Adj + Ctl
```

#### Summary
Performs the Chi function of the Keccak permutation.

#### Input
##### lanes
5x5x64 qubit array representing the state.

#### Remarks
After the state is modified, the function is inverted so the ancillary
qubits can be released.

---

### Quicc.SHA3.Iota

```
operation Iota (round : Int, lanes : Qubit[][][]) : Unit is Adj + Ctl
```

#### Summary
Performs the Iota function of the Keccak permutation.

#### Input
##### round
Current round of the Keccak permutation

##### lanes
5x5x64 qubit array representing the state.

---

### Quicc.SHA3.Keccak

```
operation Keccak ( rate : Int, suffix : Int, input : Qubit[], output : Qubit[] ) : Unit is Adj
```

#### Summary
Performs the Keccak sponge function based on the specified parameters.
Note that this operation does not support the general Keccak
specification, but is sufficient for SHA-3. It is not recommended to
invoke this operation directly. Instead, use convenience operations
such as Quicc.SHA3.SHA3_256.

#### Input
##### rate
Keccak rate parameter. For SHA-3, this is 1600 minus the capacity.

##### suffix
Delimited suffix parameter.

##### input
Input message encoded in big-endian format.

##### output
Qubit register to store the output of the Keccak algorithm.

##### References
- Keccak team website:
https://keccak.team/index.html
- FIPS 202:
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
- Extended Keccak code package (XKCP):
https://github.com/XKCP/XKCP
- Keccak tools:
https://github.com/KeccakTeam/KeccakTools

---

### Quicc.SHA3.KeccakF1600

```
operation KeccakF1600 (state : Qubit[]) : Qubit[]
```

#### Summary
Performs the Keccak-f[1600] permutation.

#### Input
##### state
1600-qubit array containing the state of the Keccak permutation.

#### Output
Modified state array.

#### See also
Quicc.SHA3.AdjointKeccakF1600

---

### Quicc.SHA3.LanesAsString<'T>

```
function LanesAsString<'T> (lanes : 'T[][][]) : 'T[]
```

#### Summary
Converts Keccak lanes back into an array.

#### Input
##### lanes
5x5x64 lane structure.

#### Type Parameters
##### 'T
Data type of lanes

#### Output
Keccak lanes as an array.

#### See also
Quicc.SHA3.StringAsLanes

---

### Quicc.SHA3.PrintLanes

```
operation PrintLanes (lanes : Qubit[][][]) : Unit
```

#### Summary
Helper operation to print the state array.

#### Input
##### lanes
5x5x64 lane structure.

---

### Quicc.SHA3.ReverseRhoPi<'T>

```
function ReverseRhoPi<'T> (lanes : 'T[][][]) : 'T[][][]
```

#### Summary
Reverses the Rho and Pi functions of the Keccak permutation.

#### Input
##### lanes
5x5x64 array representing the state.

#### Type Parameters
##### 'T
Data of `lanes`; assumed to be `Qubit`.

#### Output
Reordered 5x5x64 array.

#### See also
Quicc.SHA3.RhoPi

---

### Quicc.SHA3.RhoPi<'T>

```
function RhoPi<'T> (lanes : 'T[][][]) : 'T[][][]
```

#### Summary
Performs the Rho and Pi functions of the Keccak permutation.

#### Input
##### lanes
5x5x64 array representing the state.

#### Type Parameters
##### 'T
Data of `lanes`; assumed to be `Qubit`.

#### Output
Reordered 5x5x64 array.

#### See also
Quicc.SHA3.ReverseRhoPi

---

### Quicc.SHA3.SHA3_224

```
operation SHA3_224 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA3-224.

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.SHA3_256

```
operation SHA3_256 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA3-256.

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.SHA3_384

```
operation SHA3_384 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA3-384.

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.SHA3_512

```
operation SHA3_512 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHA3-512.

#### Input
##### input
Input message in big-endian format.

##### digest
224-qubit register to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.SHAKE128

```
operation SHAKE128 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHAKE128.

#### Input
##### input
Input message in big-endian format.

##### digest
Qubit register (of any length) to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.SHAKE256

```
operation SHAKE256 ( input : Qubit[], digest : Qubit[], workspace : Qubit[] ) : Unit is Adj
```

#### Summary
Runs a quantum implementation of SHAKE256.

#### Input
##### input
Input message in big-endian format.

##### digest
Qubit register (of any length) to store the output.

##### workspace
Unused qubit register provided for interface consistency.

---

### Quicc.SHA3.StringAsLanes<'T>

```
function StringAsLanes<'T> (str : 'T[]) : 'T[][][]
```

#### Summary
Converts an array into a 5x5x64 lane structure according to the Keccak
specification. Note that each "lane" is in little-endian format.

#### Input
##### str
Array to convert.

#### Type Parameters
##### 'T
Data type of array.

#### Output
Array as Keccak lanes.

#### See also
Quicc.SHA3.LanesAsString

---

### Quicc.SHA3.Theta

```
operation Theta (lanes : Qubit[][][]) : Unit is Adj + Ctl
```

#### Summary
Performs the Theta function of the Keccak permutation.

#### Input
##### lanes
5x5x64 qubit array representing the state.

#### Remarks
After the state is modified, the function is inverted so the ancillary
qubits can be released.

---

## Quicc.Search

### Quicc.Search.CheckSearchResult

```
operation CheckSearchResult ( oracle : ((Qubit[], Qubit) => Unit), input : Qubit[] ) : Bool
```

#### Summary
Determines if a given input causes an oracle to phase-flip a target
qubit.

#### Input
##### oracle
Operation that phase-flips a target qubit conditional on a qubit
register.

##### input
Qubit register to input to the oracle.

#### Output
`true` if the target is phase-flipped; `false` otherwise.

---

### Quicc.Search.NumIterations

```
function NumIterations (numQubits : Int, numTargets : Int) : Int
```

#### Summary
Returns the number of iterations in Grover's algorithm that maximizes
the probability of success.

#### Input
##### numQubits
Number of input qubits that will be searched over.

##### numTargets
Number of search targets.

#### Output
Optimal number of iterations.

---

### Quicc.Search.OpAsOracle

```
operation OpAsOracle ( outputLength : Int, workspaceLength : Int, outputToMatch : BigInt, op : ((Qubit[], Qubit[], Qubit[]) => Unit is Adj), input : Qubit[], target : Qubit ) : Unit is Adj
```

#### Summary
Transforms an operation into an oracle that phase-flips a target qubit
(Z gate) conditional on the output of the operation matching a
specified value.

#### Input
##### outputLength
Number of output qubits in the operation.

##### workspaceLength
Number of extra qubits needed for the operation.

##### outputToMatch
Big integer representing the output value that will cause the target
qubit to be phase-flipped

##### op
Operation taking 3 qubit arrays in order `(input, output, workspace)`.
Must support the adjoint functor.

##### input
Input qubit register.

##### target
Target qubit.

#### Remarks
To produce an oracle operation, leave the `input` and `target`
parameters as `_`.

---

### Quicc.Search.PerformSearchOnOp

```
operation PerformSearchOnOp ( numSearchTargets : Int[], inputLength : Int, outputLength: Int, workspaceLength: Int, outputToMatch : BigInt, op : ((Qubit[], Qubit[], Qubit[]) => Unit is Adj) ) : BigInt
```

#### Summary
Uses Grover's algorithm to find a corresponding input to an operation
that matches a given output.

#### Input
##### numSearchTargets
Array of integers specifying how many search targets to look for in
each run of Grover's algorithm. For example, to try Grover's algorithm
with 1 search target and then try 2 if that fails, use `[1, 2]`.

##### inputLength
Number of qubits in the input (search space).

##### outputLength
Number of output qubits in the operation.

##### workspaceLength
Number of extra qubits needed for the operation.

##### outputToMatch
Big integer representing the output for which we are trying to find a
matching input.

##### op
Operation taking 3 qubit arrays in order `(input, output, workspace)`.
Must support the adjoint functor.

#### Output
Big integer representing an input that matches the specified output if
the search succeeds; `-1L` if it fails.

---

### Quicc.Search.RunGroverOnOracle

```
operation RunGroverOnOracle ( numIterations : Int, oracle : ((Qubit[], Qubit) => Unit is Adj), input : Qubit[] ) : Unit is Adj
```

#### Summary
Runs Grover's algorithm on a phase-flip oracle.

#### Input
##### numIterations
Number of times to perform amplitude amplification.

##### oracle
Operation that phase-flips a target qubit conditional on a qubit
register. Must support the adjoint functor.

##### input
Qubit register to input to the oracle on each iteration. Will contain
the result of the algorithm after the operation.

---
