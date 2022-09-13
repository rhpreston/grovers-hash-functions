# QuICC - Quantum Implementations of Classical Cryptography

## Background

A sufficiently advanced quantum computer could perform a [preimage attack](https://en.wikipedia.org/wiki/Preimage_attack) on any black box function with a quadratic speedup over a classical computer. This implies that many current-generation cryptographic algorithms have a strength of half the original key size when attacked with such quantum computers. Realizing the attack requires two steps:

1. Implement the function as a [quantum oracle](https://docs.microsoft.com/en-us/quantum/concepts/oracles) that phase-flips a target qubit controlled on a specific output value.
1. Run [Grover's Algorithm](https://en.wikipedia.org/wiki/Grover%27s_algorithm) on the oracle to search for an input value that produces the specified output.

While it is currently infeasible to run quantum programs with hundreds of logical (error corrected) qubits, quantum software development frameworks enable them to be written and analyzed. This repository implements popular hash functions in [Q#](https://docs.microsoft.com/en-us/quantum/language/) and contains supporting code to estimate the quantum hardware resources required to reverse them. It also provides a library of unit tests to verify the correctness of each quantum operation through simulation.

The goal of this project is not to develop an optimal quantum attack against existing crypto functions. Rather, it is to explore the paradigm of quantum computing from the software engineering perspective and offer a practical example for quantum non-experts. The process of writing a program in code can also uncover details and insights that are missed in on-paper analyses.

## Setup

- Download and install [Visual Studio](https://visualstudio.microsoft.com/downloads/) with the .NET Core cross-platform development workload enabled.

- Download and install the [Microsoft Quantum Development Kit](https://marketplace.visualstudio.com/items?itemName=quantum.DevKit).

- Double-click on `quicc.sln` to open the solution in Visual Studio.

## Use

- Click **Debug** &rightarrow; **Start Without Debugging** (or press `Ctrl+F5`).

- A command window will open and display a basic CLI. Enter the number corresponding to the desired option on the main menu.

- If you select `analyze` or `simulate`, you will be prompted with a series of options that specify the quantum program under examination.

- The resource estimation or full simulation step may take some time, depending on the parameters chosen. Remember that the computational complexity on the simulator is exponential with the number of qubits in the quantum program.

- The results are displayed in the console after the run is complete. For resource estimation, [metrics](https://docs.microsoft.com/en-us/quantum/machines/resources-estimator#metrics-reported) about the program's resource requirements will be reported. For full simulation, the result of the search will be printed.

## Development

This project uses [Microsoft's Quantum Development Kit](https://www.microsoft.com/en-us/quantum/development-kit). The QDK provides a framework to write, analyze, and simulate quantum computing software. It includes the [Q# language](https://docs.microsoft.com/en-us/quantum/language/), extensive [documentation](https://docs.microsoft.com/quantum/), and a repository of tutorials called [Quantum Katas](https://github.com/microsoft/QuantumKatas). If you are new to quantum, you will probably need to spend some time with these materials before you feel comfortable working with Q#.

Contributors should follow the [Q# Style Guide](https://docs.microsoft.com/en-us/quantum/contributing/style-guide).

### Organization

The repository is organized as a Visual Studio solution with two C# projects. `App` contains the CLI and underlying functionality that make up the QuICC application. `Tests` contains unit tests for each operation in `App`. The tests are kept in a separate project so that `App` can be built without them.

The namespace hierarchy of both projects is as follows:

`Quicc`: Top-level namespace. Includes the CLI and Q# entrypoints.
- `Quicc.Common`: Utility functions and operations that are used throughout the project.
- `Quicc.CRC`: Quantum implementation of CRC.
- `Quicc.MD5`: Quantum implementation of MD5.
- `Quicc.SHA1`: Quantum implementation of SHA-1.
- `Quicc.SHA2`: Quantum implementation of SHA-2 functions, including SHA-256.
- `Quicc.SHA3`: Quantum implementation of SHA-3 functions, including SHAKE256.
- `Quicc.Search`: Operations needed to reverse a black-box function with Grover's Algorithm.

### Testing

The directory and file structure of `Tests` should match that of `App` as much as possible. See the [Q# doc page on testing and debugging](https://docs.microsoft.com/en-us/quantum/techniques/testing-and-debugging) for information on writing unit tests. This project makes use of the `@Test("...")` attribute to indicate an operation should be run on the specified execution target. Note the difference between `@Test("QuantumSimulator")` tests, which run on the [full state simulator](https://docs.microsoft.com/en-us/quantum/machines/full-state-simulator), and `@Test("ToffoliSimulator")` tests, which run on the [Toffoli simulator](https://docs.microsoft.com/en-us/quantum/machines/toffoli-simulator).

To run the unit tests, click **Test** &rightarrow; **Run All Tests**, (or press `Ctrl+R, A`). View the results in the Test Explorer pane.

### Documentation

The [API documentation](API.md) is generated from the `///` comments preceding Q# operations and functions in the `App` project. A custom [Python script](generate_docs.py) parses each source file and consolidates them into one document. To run it, ensure [Python 3](https://www.python.org/downloads/) is installed on your machine and run it from the command line with `py generate_docs.py`. Note that there are likely to be better options available for generating Q# API documentation in the future.

## License

Copyright (C) 2022 The MITRE Corporation. All Rights Reserved. Approved for Public Release; Distribution Unlimited. Public Release Case #22-2203.

This project contains content developed by The MITRE Corporation. If this code is used in a deployment or embedded within another project, it is requested that you send an email to [opensource@mitre.org](mailto:opensource@mitre.org) in order to let us know where this software is being used.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
