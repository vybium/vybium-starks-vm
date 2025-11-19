package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/pkg/vybium-starks-vm"
)

// Input format matches Triton VM's interface
type ClaimInput struct {
	ProgramDigest string   `json:"program_digest"` // Hex string
	Version       uint32   `json:"version"`
	Input         []uint64 `json:"input"`
	Output        []uint64 `json:"output"`
}

type ProgramInput struct {
	Instructions   []string               `json:"instructions"` // String format like "Halt", "Push(42)"
	AddressToLabel map[string]uint64      `json:"address_to_label,omitempty"`
	DebugInfo      map[string]interface{} `json:"debug_information,omitempty"`
}

type NonDeterminismInput struct {
	IndividualTokens []uint64          `json:"individual_tokens"`
	Digests          []string          `json:"digests"`
	Ram              map[string]uint64 `json:"ram"`
}

func main() {
	// Read JSON lines from stdin (like Triton VM prover)
	scanner := bufio.NewScanner(os.Stdin)

	// Line 1: Claim
	if !scanner.Scan() {
		fatal("Failed to read claim")
	}
	var claimInput ClaimInput
	if err := json.Unmarshal(scanner.Bytes(), &claimInput); err != nil {
		fatal(fmt.Sprintf("Failed to parse claim: %v", err))
	}

	// Line 2: Program
	if !scanner.Scan() {
		fatal("Failed to read program")
	}
	var programInput ProgramInput
	if err := json.Unmarshal(scanner.Bytes(), &programInput); err != nil {
		fatal(fmt.Sprintf("Failed to parse program: %v", err))
	}

	// Line 3: NonDeterminism
	if !scanner.Scan() {
		fatal("Failed to read non_determinism")
	}
	var nonDetInput NonDeterminismInput
	if err := json.Unmarshal(scanner.Bytes(), &nonDetInput); err != nil {
		fatal(fmt.Sprintf("Failed to parse non_determinism: %v", err))
	}

	// Line 4: Max padded height (optional)
	if !scanner.Scan() {
		fatal("Failed to read max_log2_padded_height")
	}
	var maxPaddedHeight *uint8
	if err := json.Unmarshal(scanner.Bytes(), &maxPaddedHeight); err != nil {
		fatal(fmt.Sprintf("Failed to parse max_log2_padded_height: %v", err))
	}

	// Line 5: Environment variables
	if !scanner.Scan() {
		fatal("Failed to read env_variables")
	}
	var envVars map[string]interface{}
	if err := json.Unmarshal(scanner.Bytes(), &envVars); err != nil {
		fatal(fmt.Sprintf("Failed to parse env_variables: %v", err))
	}

	// Convert inputs to Vybium STARKs VM format
	program, err := convertProgram(programInput)
	if err != nil {
		fatal(fmt.Sprintf("Failed to convert program: %v", err))
	}

	publicInput := convertFieldElements(claimInput.Input)
	secretInput := convertFieldElements(nonDetInput.IndividualTokens)

	// Create VM and execute
	logStderr("Creating Riva VM...")
	vm, err := vybiumstarksvm.NewVM(vybiumstarksvm.DefaultVMConfig())
	if err != nil {
		fatal(fmt.Sprintf("Failed to create VM: %v", err))
	}

	// Execute program
	logStderr("Executing program...")
	trace, err := vm.Execute(program, publicInput, secretInput)
	if err != nil {
		fatal(fmt.Sprintf("Execution failed: %v", err))
	}

	logStderr(fmt.Sprintf("Execution completed in %d cycles", trace.CycleCount))

	// Create prover with proper security parameters
	config := vybiumstarksvm.DefaultConfig()
	config.FRIQueries = 80 // 128-bit security requires SecurityLevel/3 = 240/3 = 80

	// Adjust config based on padded height if needed
	if maxPaddedHeight != nil {
		logStderr(fmt.Sprintf("Max log2 padded height: %d", *maxPaddedHeight))
	}

	logStderr("Creating prover...")
	prover, err := vybiumstarksvm.NewProver(config)
	if err != nil {
		fatal(fmt.Sprintf("Failed to create prover: %v", err))
	}

	// Generate proof
	logStderr("Generating proof...")
	proof, err := prover.GenerateProof(trace)
	if err != nil {
		fatal(fmt.Sprintf("Proof generation failed: %v", err))
	}

	logStderr("Proof generated successfully")

	// Serialize proof
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		fatal(fmt.Sprintf("Failed to serialize proof: %v", err))
	}

	// Write proof to stdout (like Triton VM)
	os.Stdout.Write(proofBytes)
	os.Stdout.Write([]byte("\n"))
}

func convertProgram(input ProgramInput) (*vybiumstarksvm.Program, error) {
	instructions := make([]vybiumstarksvm.Instruction, len(input.Instructions))

	for i, instStr := range input.Instructions {
		opcode, arg, err := parseInstruction(instStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse instruction %d (%s): %w", i, instStr, err)
		}

		instructions[i] = vybiumstarksvm.Instruction{
			Opcode:   opcode,
			Argument: arg,
		}
	}

	return &vybiumstarksvm.Program{
		Instructions: instructions,
	}, nil
}

func parseInstruction(instStr string) (byte, *vybiumstarksvm.FieldElement, error) {
	// Parse Triton VM instruction format: "Halt", "Push(42)", "ReadIo(1)", etc.

	// Simple instructions without arguments
	switch instStr {
	case "Halt":
		return 0, nil, nil
	case "Divine":
		return 2, nil, nil
	case "Return":
		return 8, nil, nil
	case "Dup":
		return 5, nil, nil
	case "Eq":
		return 6, nil, nil
	case "Skiz":
		return 7, nil, nil
	case "Recurse":
		return 10, nil, nil
	case "Add":
		return 42, nil, nil
	case "Mul":
		return 43, nil, nil
	}

	// Instructions with arguments: "Push(42)", "ReadIo(1)", etc.
	if strings.Contains(instStr, "(") {
		parts := strings.Split(instStr, "(")
		if len(parts) != 2 {
			return 0, nil, fmt.Errorf("invalid instruction format: %s", instStr)
		}

		opName := parts[0]
		argStr := strings.TrimSuffix(parts[1], ")")

		// Parse argument as uint64
		var argVal uint64
		_, err := fmt.Sscanf(argStr, "%d", &argVal)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid argument: %s", argStr)
		}

		arg := convertFieldElement(argVal)

		switch opName {
		case "Push":
			return 1, arg, nil
		case "ReadIo":
			return 3, arg, nil
		case "WriteIo":
			return 4, arg, nil
		case "Call":
			return 9, arg, nil
		default:
			return 0, nil, fmt.Errorf("unknown instruction: %s", opName)
		}
	}

	return 0, nil, fmt.Errorf("unknown instruction: %s", instStr)
}

func convertFieldElements(values []uint64) []*vybiumstarksvm.FieldElement {
	result := make([]*vybiumstarksvm.FieldElement, len(values))
	for i, val := range values {
		result[i] = convertFieldElement(val)
	}
	return result
}

func convertFieldElement(val uint64) *vybiumstarksvm.FieldElement {
	// Create the Goldilocks field
	modulus := new(big.Int)
	modulus.SetString("18446744069414584321", 10)
	coreField, err := core.NewField(modulus)
	if err != nil {
		fatal(fmt.Sprintf("Failed to create field: %v", err))
	}

	// Create element with the value
	bigVal := new(big.Int).SetUint64(val)
	return coreField.NewElement(bigVal)
}

func logStderr(msg string) {
	fmt.Fprintln(os.Stderr, "riva-vm:", msg)
}

func fatal(msg string) {
	logStderr("ERROR: " + msg)
	os.Exit(1)
}
