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

namespace Quicc {

    open Microsoft.Quantum.Canon;
    open Microsoft.Quantum.Intrinsic;

    open Quicc.Search;
    open Quicc.CRC;
    open Quicc.MD5;
    open Quicc.SHA1;
    open Quicc.SHA2;
    open Quicc.SHA3;


    /// # Summary
    /// Attempts to reverse CRC8 with Grover's algorithm.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchCRC8 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            8,
            0,
            outputToMatch,
            CRC8
        );
    }

    /// # Summary
    /// Attempts to reverse CRC16 with Grover's algorithm.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchCRC16 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            16,
            0,
            outputToMatch,
            CRC16
        );
    }

    /// # Summary
    /// Attempts to reverse CRC32 with Grover's algorithm.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchCRC32 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            32,
            0,
            outputToMatch,
            CRC32
        );
    }

    /// # Summary
    /// Conducts a preimage attack against MD5. That is, attempts to find a
    /// message with specified length whose MD5 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchMD5 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            128,
            MD5WorkspaceRequirement(inputLength),
            outputToMatch,
            MD5
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-1. That is, attempts to find a
    /// message with specified length whose SHA-1 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA1 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            160,
            SHA1WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA1
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-224. That is, attempts to find a
    /// message with specified length whose SHA-224 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA224 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            224,
            SHA224WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA224
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-256. That is, attempts to find a
    /// message with specified length whose SHA-256 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA256 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            256,
            SHA256WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA256
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-348. That is, attempts to find a
    /// message with specified length whose SHA-348 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA384 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            384,
            SHA384WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA384
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-512. That is, attempts to find a
    /// message with specified length whose SHA-512 digest is some given value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA512 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            512,
            SHA512WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA512
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-512/224. That is, attempts to
    /// find a message with specified length whose SHA-512 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA512_224 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            224,
            SHA512_224WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA512_224
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA-512/256. That is, attempts to
    /// find a message with specified length whose SHA-512 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA512_256 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            256,
            SHA512_256WorkspaceRequirement(inputLength),
            outputToMatch,
            SHA512_256
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHAKE128. That is, attempts to find
    /// a message with specified length whose SHAKE128 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputLength
    /// Number of qubits in SHAKE128 output.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHAKE128 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            outputLength,
            0,
            outputToMatch,
            SHAKE128
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHAKE256. That is, attempts to find
    /// a message with specified length whose SHAKE256 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputLength
    /// Number of qubits in SHAKE128 output.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHAKE256 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            outputLength,
            0,
            outputToMatch,
            SHAKE256
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA3-224. That is, attempts to find
    /// a message with specified length whose SHA3-224 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA3_224 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            224,
            0,
            outputToMatch,
            SHA3_224
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA3-256. That is, attempts to find
    /// a message with specified length whose SHA3-256 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA3_256 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            256,
            0,
            outputToMatch,
            SHA3_256
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA3-384. That is, attempts to find
    /// a message with specified length whose SHA3-384 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA3_384 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            256,
            0,
            outputToMatch,
            SHA3_384
        );
    }

    /// # Summary
    /// Conducts a preimage attack against SHA3-512. That is, attempts to find
    /// a message with specified length whose SHA3-512 digest is some given
    /// value.
    /// 
    /// # Input
    /// ## numSearchTargets
    /// Array of integers specifying how many search targets to look for in
    /// each run of Grover's algorithm. It's recommended to use a predefined
    /// search strategy to generate this parameter.
    /// 
    /// ## inputLength
    /// Number of qubits in input message we are looking for.
    /// 
    /// ## outputToMatch
    /// Big integer representing the output for which we are trying to find a
    /// matching input.
    /// 
    /// # Output
    /// Big integer representing an input that matches the specified output if
    /// the search succeeds; `-1L` if it fails.
    operation SearchSHA3_512 (
        numSearchTargets : Int[],
        inputLength : Int,
        outputToMatch : BigInt
    ) : BigInt {
        return PerformSearchOnOp(
            numSearchTargets,
            inputLength,
            512,
            0,
            outputToMatch,
            SHA3_512
        );
    }
}
