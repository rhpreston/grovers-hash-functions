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

using Microsoft.Quantum.Simulation.Core;
using Microsoft.Quantum.Simulation.Simulators;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Threading.Tasks;

namespace Quicc
{
    class Driver
    {
        static void Main()
        {
            PrintWelcome();

            while (true)
            {
                string[] menuOptions = { "analyze", "simulate", "help", "quit" };
                string option = GetOption("Main menu:", menuOptions);

                if (option == "help") { PrintHelp(); continue; }
                if (option == "quit") { break; }

                string op;
                if (option == "analyze") { op = GetOperationToAnalyze(); }
                else { op = GetOperationToSimulate(); }

                long[] numSearchTargets = GetSearchMethod();
                int inputLength = GetInputLength();
                int outputLength = LookupOutputLength(op);
                BigInteger outputToMatch = GetOutputToMatch(outputLength);
                var entrypoint = LookupEntrypoint(op, numSearchTargets,
                                                  inputLength, outputLength,
                                                  outputToMatch);

                if (option == "analyze") { EstimateResources(entrypoint); }
                else { RunSimulation(entrypoint); }
            }
        }

        /// <summary>
        /// Prints a startup message to the console.
        /// </summary>
        static void PrintWelcome()
        {
            Console.WriteLine(
"\n         . | .       " +
"\n     .    .|  /  .   " +
"\n   .       | /     . " +
"\n         . |/        " +
"\n  ---------+---------  Welcome to QuICC. Use this app to analyze quantum" +
"\n   .     ./|       .   preimage attacks on certain crypto functions." +
"\n     .   /.|     .   " +
"\n        /. | .       " +
"\n           |         " +
"\n");
        }

        /// <summary>
        /// Prints a help message to the console.
        /// </summary>
        static void PrintHelp()
        {
            Console.WriteLine(
"\nQuICC implements popular hash functions as quantum oracles. Given a" +
"\nspecific output to an oracle, a sufficiently advanced quantum computer" +
"\ncould search for a matching input faster than a classical one. This app" +
"\nallows the user to estimate the quantum computing resources required to" +
"\nrun such a program. Operations that are small enough can also be fully" +
"\nsimulated." +
"\n" +
"\nMain menu options" +
"\n-----------------" +
"\n analyze:" +
"\n     Run a search with the resource estimator. Reports metrics about the" +
"\n     program's resource requirements, but does not actually conduct the" +
"\n     search." +
"\n simulate:" +
"\n     Run a search with the full simulator. Since this is computationally" +
"\n     intensive, fewer operations are available for full simulation." +
"\n help:" +
"\n     Print this message." +
"\n quit:" +
"\n     Quit the application." +
"\n" +
"\nSearch parameters" +
"\n-----------------" +
"\n Search method:" +
"\n     How many matching inputs are expected for the given output, i.e.," +
"\n     the number of search targets for Grover's Algorithm." +
"\n      - single: 1 search target expected" +
"\n      - multiple: User enters number of search targets expected" +
"\n      - arithmetic: Starts with 1 target, then increments by 1 after each" +
"\n         failed search until max number entered by the user is reached" +
"\n      - geometric: Starts with 1 target, then multiplies by 2 after each" +
"\n         failed search for the number of attempts entered by the user" +
"\n Search space size:" +
"\n     How many bits in the input to search for. Computational complexity" +
"\n     increases exponentially with this parameter." +
"\n Known output to match:" +
"\n     Hex value of hash digest to search a matching input for. Must be in" +
"\n     the appropriate range for the selected operation." +
"\n");
        }

        /// <summary>
        /// Prints the elapsed time to the console.
        /// </summary>
        /// <param name="elapsed">TimeSpan object.</param>
        static void PrintRuntime(TimeSpan elapsed)
        {
            Console.WriteLine("\nRuntime: {0:00}:{1:00}:{2:00}.{3:00}",
                      elapsed.Hours, elapsed.Minutes, elapsed.Seconds,
                      elapsed.Milliseconds / 10);
        }

        /// <summary>
        /// Prompts the user to select an operation to analyze.
        /// </summary>
        /// <returns>String containing selected operation.</returns>
        static string GetOperationToAnalyze()
        {
            string[] ops =
            {
                "CRC-8",
                "CRC-16",
                "CRC-32",
                "MD5",
                "SHA-1",
                "SHA-224",
                "SHA-256",
                "SHA-384",
                "SHA-512",
                "SHA-512/224",
                "SHA-512/256",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
                "SHAKE128",
                "SHAKE256"
            };
            return GetOption("Choose an operation to analyze:", ops);

        }

        /// <summary>
        /// Prompts the user to select an operation to simulate.
        /// </summary>
        /// <returns>String containing selected operation.</returns>
        static string GetOperationToSimulate()
        {
            string[] ops =
            {
                "CRC-8",
                "CRC-16"
            };
            return GetOption("Choose an operation to simulate:", ops);

        }

        /// <summary>
        /// Returns the bit-length of the output of a given operation.
        /// </summary>
        /// <param name="Op">String specifying operation in question.</param>
        /// <returns>Integer bit-length.</returns>
        static int LookupOutputLength(string Op)
        {
            int outputLength = Op switch
            {
                "CRC-8" => 8,
                "CRC-16" => 16,
                "CRC-32" => 32,
                "MD5" => 128,
                "SHA-1" => 160,
                "SHA-224" => 224,
                "SHA-256" => 256,
                "SHA-384" => 384,
                "SHA-512" => 512,
                "SHA-512/224" => 224,
                "SHA-512/256" => 256,
                "SHA3-224" => 224,
                "SHA3-256" => 256,
                "SHA3-384" => 384,
                "SHA3-512" => 512,
                "SHAKE128" => GetInt("Output length?"),
                "SHAKE256" => GetInt("Output length?"),
                _ => throw new NotImplementedException(),
            };
            return outputLength;
        }

        /// <summary>
        /// Prompts the user to select a search method and generates the
        /// appropriate search target sequence.
        /// </summary>
        /// <returns>Integer array containing search target sequence.</returns>
        static long[] GetSearchMethod()
        {
            string[] methods =
            {
                "single",
                "multiple",
                "arithmetic",
                "geometric"
            };
            string method = GetOption("Choose a search method:", methods);

            if (method == "single")
            {
                return new long[] { 1 };
            }

            if (method == "multiple")
            {
                int numTargets = GetInt("Number of search targets?", 2);
                return new long[] { numTargets };
            }

            if (method == "arithmetic")
            {
                int maxTargets = GetInt("Max number of search targets?", 2);
                long[] sequence = new long[maxTargets];
                for (int i = 0; i < maxTargets; i++)
                {
                    sequence[i] = 1 + i;
                }
                return sequence;
            }

            if (method == "geometric")
            {
                int numAttempts = GetInt("Number of search attempts?", 2, 31);
                long[] sequence = new long[numAttempts];
                for (int i = 0; i < numAttempts; i++)
                {
                    sequence[i] = 1 << i;
                }
                return sequence;
            }

            throw new NotImplementedException();
        }

        /// <summary>
        /// Prompts the user to specify the size of the search space in bits.
        /// </summary>
        /// <returns>Integer that was specified.</returns>
        static int GetInputLength()
        {
            return GetInt("Enter size of search space in bits (<63):", 1, 62);
        }

        /// <summary>
        /// Prompts the user to enter the known output for which to find a
        /// matching input in hex format.
        /// </summary>
        /// <param name="outputLength">
        ///     Number of bits in output of crypto function.
        /// </param>
        /// <returns>Big integer that was entered.</returns>
        static BigInteger GetOutputToMatch(int outputLength)
        {
            return GetBigInteger(
                "Enter known output for which to find a matching input (hex):",
                ((BigInteger) 1 << outputLength) - 1,
                NumberStyles.AllowHexSpecifier
            );
        }

        /// <summary>
        /// Perform an analysis of the quantum hardware resources required to
        /// run a given program.
        /// </summary>
        /// <param name="Program">
        ///     Quantum program to estimate resources of.
        /// </param>
        static void EstimateResources(
            Func<IOperationFactory,Task<BigInteger>> Program)
        {
            Console.Write("\nEstimating resources...");
            ResourcesEstimator estimator = new ResourcesEstimator();

            var stopwatch = Stopwatch.StartNew();
            Program(estimator).Wait();
            stopwatch.Stop();

            Console.WriteLine("Done");
            PrintRuntime(stopwatch.Elapsed);
            Console.WriteLine("\nResults\n--------------------");
            Console.WriteLine(estimator.ToTSV());
        }

        /// <summary>
        /// Run a simulation of a given program.
        /// </summary>
        /// <param name="Program">Quantum program to simulate.</param>
        static void RunSimulation(
            Func<IOperationFactory, Task<BigInteger>> Program)
        {
            Console.Write("\nSimulating quantum program...");
            using var simulator = new QuantumSimulator();

            var stopwatch = Stopwatch.StartNew();
            var result = Program(simulator).Result;
            stopwatch.Stop();

            Console.WriteLine("Done");
            PrintRuntime(stopwatch.Elapsed);
            if (result == -1L)
            {
                Console.WriteLine("\nSearch failed.");
            }
            else
            {
                Console.WriteLine("\nSearch result (hex): {0:X}", result);
            }
        }

        /// <summary>
        /// Generates an entrypoint for running a preimage search on a
        /// specified crypto function implemented in Q#.
        /// </summary>
        /// <param name="Op">String specifying quantum operation.</param>
        /// <param name="NumSearchTargets">
        ///     Integer array containing search target sequence.
        /// </param>
        /// <param name="InputLength">Size of search space in bits.</param>
        /// <param name="OutputLength">Size of function output in bits.</param>
        /// <param name="OutputToMatch">
        ///     Number of bits in output of crypto function.
        /// </param>
        /// <returns></returns>
        static Func<IOperationFactory,Task<BigInteger>> LookupEntrypoint(
            string Op, long[] NumSearchTargets, int InputLength,
            int OutputLength, BigInteger OutputToMatch)
        {
            var targets = new QArray<long>(NumSearchTargets);

            Func<IOperationFactory,Task<BigInteger>> entrypoint = Op switch
            {
                "CRC-8" => (
                    (f) => SearchCRC8.Run(f, targets, InputLength, OutputToMatch)
                ),
                "CRC-16" => (
                    (f) => SearchCRC16.Run(f, targets, InputLength, OutputToMatch)
                ),
                "CRC-32" => (
                    (f) => SearchCRC32.Run(f, targets, InputLength, OutputToMatch)
                ),
                "MD5" => (
                    (f) => SearchMD5.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-1" => (
                    (f) => SearchSHA1.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-224" => (
                    (f) => SearchSHA224.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-256" => (
                    (f) => SearchSHA256.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-384" => (
                    (f) => SearchSHA384.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-512" => (
                    (f) => SearchSHA512.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-512/224" => (
                    (f) => SearchSHA512_224.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA-512/256" => (
                    (f) => SearchSHA512_256.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA3-224" => (
                    (f) => SearchSHA3_224.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA3-256" => (
                    (f) => SearchSHA3_256.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA3-384" => (
                    (f) => SearchSHA3_384.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHA3-512" => (
                    (f) => SearchSHA3_512.Run(f, targets, InputLength, OutputToMatch)
                ),
                "SHAKE128" => (
                    (f) => SearchSHAKE128.Run(f, targets, InputLength, OutputLength, OutputToMatch)
                ),
                "SHAKE256" => (
                    (f) => SearchSHAKE256.Run(f, targets, InputLength, OutputLength, OutputToMatch)
                ),
                _ => throw new NotImplementedException(),
            };
            return entrypoint;
        }

        /// <summary>
        /// Gets an integer input from the console.
        /// </summary>
        /// <param name="Prompt">String to prompt the user with.</param>
        /// <param name="Min">Minimum accepted number for the input.</param>
        /// <param name="Max">Maximum accepted number for the input.</param>
        /// <returns>Integer that was input.</returns>
        static int GetInt(string Prompt, int Min = int.MinValue,
                          int Max = int.MaxValue)
        {
            while (true)
            {
                Console.WriteLine("\n" + Prompt);
                Console.Write("> ");

                if (int.TryParse(Console.ReadLine(), out int value))
                {
                    if (Min <= value && value <= Max)
                    {
                        return value;
                    }
                }

                Console.WriteLine("Invalid input");
            }
        }

        /// <summary>
        /// Presents the user with a set of options and returns the selected
        /// one.
        /// </summary>
        /// <param name="Prompt">String to prompt the user with.</param>
        /// <param name="Options">Array of string options.</param>
        /// <returns>Selected string option.</returns>
        static string GetOption(string Prompt, string[] Options)
        {
            for (int i = 1; i <= Options.Length; i++)
            {
                Prompt += $"\n [{i}] {Options[i - 1]}";
            }

            int selection = GetInt(Prompt, 1, Options.Length);
            Console.WriteLine(Options[selection - 1]);
            return Options[selection - 1];
        }

        /// <summary>
        /// Gets a positive big integer input from the console.
        /// </summary>
        /// <param name="Prompt">String to prompt the user with.</param>
        /// <param name="Max">Maximum accepted number for the input.</param>
        /// <param name="Style">Number style of the input.</param>
        /// <returns>Big integer that was input.</returns>
        static BigInteger GetBigInteger(string Prompt, BigInteger Max,
                                        NumberStyles Style)
        {
            while (true)
            {
                Console.WriteLine("\n" + Prompt);
                Console.Write("> ");

                string input = "0" + Console.ReadLine();

                if (BigInteger.TryParse(input, Style, null, out BigInteger value))
                {
                    if (value <= Max)
                    {
                        return value;
                    }
                }

                Console.WriteLine("Invalid input");
            }
        }
    }
}