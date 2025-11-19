// Package vybiumstarksvm provides a production-ready zkSTARKs implementation with Vybium STARKs VM.
//
// Vybium STARKs VM is a zero-knowledge Scalable Transparent Argument of Knowledge (zkSTARK)
// system with a complete virtual machine implementation.
//
// # Features
//
// - Complete zkSTARK prover and verifier
// - Vybium STARKs VM with 47-instruction ISA
// - Cascade lookup tables for efficient U32 operations
// - Program attestation for recursive verification
// - Run-time permutation checks
// - Poseidon hash function with Grain LFSR and Cauchy MDS
// - Field-friendly cryptographic primitives
//
// # Quick Start
//
// Creating a prover and generating a proof:
//
//	config := vybiumstarksvm.DefaultConfig()
//	prover, err := vybiumstarksvm.NewProver(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Generate proof from execution trace
//	proof, err := prover.GenerateProof(trace)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Creating a verifier and verifying a proof:
//
//	config := vybiumstarksvm.DefaultConfig()
//	verifier, err := vybiumstarksvm.NewVerifier(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Verify the proof
//	result, err := verifier.VerifyProof(proof, claim)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if result.Valid {
//		fmt.Println("Proof is valid!")
//	}
//
// # Using the Vybium STARKs VM
//
// Executing a program on the VM:
//
//	vmConfig := vybiumstarksvm.DefaultVMConfig()
//	vm, err := vybiumstarksvm.NewVM(vmConfig)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create a simple program
//	program := &vybiumstarksvm.Program{
//		Instructions: []vybiumstarksvm.Instruction{
//			{Opcode: 0x01, Argument: nil}, // Push
//			{Opcode: 0x00, Argument: nil}, // Halt
//		},
//	}
//
//	// Execute the program
//	trace, err := vm.Execute(program, publicInput, secretInput)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Architecture
//
// Vybium STARKs VM uses a hybrid public/private architecture:
//
// - pkg/vybium-starks-vm/: Public API (this package)
// - internal/vybium-starks-vm/: Private implementation (not importable)
//
// The public API provides stable interfaces for:
// - STARK proving and verification
// - VM execution
// - Common types and errors
//
// Implementation details in internal/ can be refactored without breaking the public API.
//
// # Implementation Features
//
// Vybium STARKs VM provides a comprehensive Poseidon implementation with:
// - Dynamic Grain LFSR parameter generation (no large precomputed constant files)
// - Runtime Cauchy MDS matrix construction with cryptographic guarantees
// - Full sponge construction for variable-length inputs/outputs
// - Multi-field support for various prime fields
// - Configurable security levels with automatic parameter optimization
//
// # Performance
//
// Benchmark results on Intel i9-14900HX:
// - Enhanced Hash (128-bit): 2.5 ms/op
// - Grain LFSR: 12.5 μs/op
// - MDS Matrix Generation: 6.8 μs/op
// - Full Round: 6.0 μs/op
//
// # References
//
// - STARK Paper: https://eprint.iacr.org/2018/046
// - FRI Paper: https://eccc.weizmann.ac.il/report/2017/134/
//
// # License
//
// See LICENSE file in the repository root.
package vybiumstarksvm
