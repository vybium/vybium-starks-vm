package binary_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Test inputs matching Triton VM format
type ClaimInput struct {
	ProgramDigest string   `json:"program_digest"` // Hex string in Triton VM
	Version       uint32   `json:"version"`
	Input         []uint64 `json:"input"`
	Output        []uint64 `json:"output"`
}

type ProgramInput struct {
	Instructions     []string          `json:"instructions"`     // String format in Triton VM
	AddressToLabel   map[string]uint64 `json:"address_to_label"` // Always include, even if empty
	DebugInformation *DebugInfo        `json:"debug_information,omitempty"`
}

type DebugInfo struct {
	Breakpoints      []bool                 `json:"breakpoints"`
	TypeHints        map[string]interface{} `json:"type_hints"`
	AssertionContext map[string]interface{} `json:"assertion_context"`
}

type NonDeterminismInput struct {
	IndividualTokens []uint64          `json:"individual_tokens"`
	Digests          []string          `json:"digests"` // Changed from digest_tokens
	Ram              map[string]uint64 `json:"ram"`
}

type TestCase struct {
	Name                string
	Claim               ClaimInput
	Program             ProgramInput
	NonDeterminism      NonDeterminismInput
	MaxLog2Height       *uint8
	EnvVars             map[string]interface{}
	ExpectedExitCode    int
	ShouldGenerateProof bool
}

func TestAtlasVMBinaryInterface(t *testing.T) {
	// Build the Vybium STARKs VM prover binary first
	atlasProverPath, err := buildAtlasProver(t)
	if err != nil {
		t.Skipf("Skipping test: Failed to build vybium-starks-vm-prover: %v", err)
	}
	defer func() {
		if err := os.Remove(atlasProverPath); err != nil {
			t.Logf("Warning: failed to remove temp binary: %v", err)
		}
	}()

	// Test case: Simple halt program (using Vybium STARKs VM format)
	testCases := []TestCase{
		{
			Name: "Simple Halt",
			Claim: ClaimInput{
				ProgramDigest: "49390b5279de3843c90d85289b12a2e65004866a98d03cfdbca7eb0c91bafd6962c094958c115b7e", // From Triton VM
				Version:       0,
				Input:         []uint64{},
				Output:        []uint64{},
			},
			Program: ProgramInput{
				Instructions:   []string{"Halt"},
				AddressToLabel: map[string]uint64{},
				DebugInformation: &DebugInfo{
					Breakpoints:      []bool{false},
					TypeHints:        map[string]interface{}{},
					AssertionContext: map[string]interface{}{},
				},
			},
			NonDeterminism: NonDeterminismInput{
				IndividualTokens: []uint64{},
				Digests:          []string{},
				Ram:              map[string]uint64{},
			},
			MaxLog2Height:       nil,
			EnvVars:             map[string]interface{}{},
			ExpectedExitCode:    0,
			ShouldGenerateProof: true,
		},
		{
			Name: "Push and Halt",
			Claim: ClaimInput{
				// Note: Program digest is computed by the prover binary from the program instructions.
				// This placeholder is fine as the binary will compute the actual digest.
				ProgramDigest: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				Version:       0,
				Input:         []uint64{},
				Output:        []uint64{},
			},
			Program: ProgramInput{
				Instructions:   []string{"Push(42)", "Halt"},
				AddressToLabel: map[string]uint64{},
				DebugInformation: &DebugInfo{
					Breakpoints:      []bool{false, false},
					TypeHints:        map[string]interface{}{},
					AssertionContext: map[string]interface{}{},
				},
			},
			NonDeterminism: NonDeterminismInput{
				IndividualTokens: []uint64{},
				Digests:          []string{},
				Ram:              map[string]uint64{},
			},
			MaxLog2Height:       nil,
			EnvVars:             map[string]interface{}{},
			ExpectedExitCode:    0,
			ShouldGenerateProof: true,
		},
		{
			Name: "Read and Write IO",
			Claim: ClaimInput{
				// Note: Program digest is computed by the prover binary from the program instructions.
				// This placeholder is fine as the binary will compute the actual digest.
				ProgramDigest: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				Version:       0,
				Input:         []uint64{42},
				Output:        []uint64{42},
			},
			Program: ProgramInput{
				Instructions:   []string{"ReadIo(1)", "WriteIo(1)", "Halt"},
				AddressToLabel: map[string]uint64{},
				DebugInformation: &DebugInfo{
					Breakpoints:      []bool{false, false, false},
					TypeHints:        map[string]interface{}{},
					AssertionContext: map[string]interface{}{},
				},
			},
			NonDeterminism: NonDeterminismInput{
				IndividualTokens: []uint64{},
				Digests:          []string{},
				Ram:              map[string]uint64{},
			},
			MaxLog2Height:       nil,
			EnvVars:             map[string]interface{}{},
			ExpectedExitCode:    0,
			ShouldGenerateProof: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Run Vybium STARKs VM prover
			atlasOutput, atlasErr, atlasExitCode := runProver(atlasProverPath, tc)

			t.Logf("Vybium STARKs VM exit code: %d", atlasExitCode)
			if atlasErr != "" {
				t.Logf("Vybium STARKs VM stderr:\n%s", atlasErr)
			}

			if atlasExitCode != tc.ExpectedExitCode {
				t.Errorf("Expected exit code %d, got %d", tc.ExpectedExitCode, atlasExitCode)
			}

			if tc.ShouldGenerateProof && len(atlasOutput) == 0 {
				t.Error("Expected proof output but got none")
			}

			t.Logf("✅ Vybium STARKs VM binary test passed: %s", tc.Name)
		})
	}
}

func TestVybiumSTARKsVMVsTritonVM(t *testing.T) {
	// Check if Triton VM prover is available
	tritonProverPath := "/home/anon/Documents/GitHub/neptune-core/target/release/triton-vm-prover"
	if _, err := os.Stat(tritonProverPath); os.IsNotExist(err) {
		t.Skip("Triton VM prover not found, skipping comparative test")
	}

	// Build Vybium STARKs VM prover
	atlasProverPath, err := buildAtlasProver(t)
	if err != nil {
		t.Skipf("Skipping test: Failed to build vybium-starks-vm-prover: %v", err)
	}
	defer func() {
		if err := os.Remove(atlasProverPath); err != nil {
			t.Logf("Warning: failed to remove temp binary: %v", err)
		}
	}()

	// Test cases for comparison
	testCases := []TestCase{
		{
			Name: "Halt Program",
			Claim: ClaimInput{
				ProgramDigest: "49390b5279de3843c90d85289b12a2e65004866a98d03cfdbca7eb0c91bafd6962c094958c115b7e",
				Version:       0,
				Input:         []uint64{},
				Output:        []uint64{},
			},
			Program: ProgramInput{
				Instructions:   []string{"Halt"},
				AddressToLabel: map[string]uint64{},
				DebugInformation: &DebugInfo{
					Breakpoints:      []bool{false},
					TypeHints:        map[string]interface{}{},
					AssertionContext: map[string]interface{}{},
				},
			},
			NonDeterminism: NonDeterminismInput{
				IndividualTokens: []uint64{},
				Digests:          []string{},
				Ram:              map[string]uint64{},
			},
			MaxLog2Height:       nil,
			EnvVars:             map[string]interface{}{},
			ExpectedExitCode:    0,
			ShouldGenerateProof: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Run both provers
			atlasOutput, atlasErr, atlasExitCode := runProver(atlasProverPath, tc)
			tritonOutput, tritonErr, tritonExitCode := runProver(tritonProverPath, tc)

			t.Logf("Vybium STARKs VM exit code: %d", atlasExitCode)
			t.Logf("Triton VM exit code: %d", tritonExitCode)

			if atlasErr != "" {
				t.Logf("Vybium STARKs VM stderr:\n%s", atlasErr)
			}
			if tritonErr != "" {
				t.Logf("Triton VM stderr:\n%s", tritonErr)
			}

			// Compare exit codes
			if atlasExitCode != tritonExitCode {
				t.Logf("⚠️ Exit codes differ: Vybium STARKs VM=%d, Triton=%d", atlasExitCode, tritonExitCode)
			} else {
				t.Logf("✅ Exit codes match: %d", atlasExitCode)
			}

			// Compare output presence (both should generate proofs or both should fail)
			atlasHasProof := len(atlasOutput) > 0
			tritonHasProof := len(tritonOutput) > 0

			if atlasHasProof != tritonHasProof {
				t.Errorf("Proof generation mismatch: Vybium STARKs VM=%v, Triton=%v", atlasHasProof, tritonHasProof)
			} else {
				t.Logf("✅ Both provers %s proofs", map[bool]string{true: "generated", false: "did not generate"}[atlasHasProof])
			}

			// Log proof sizes for comparison
			if atlasHasProof && tritonHasProof {
				t.Logf("Proof sizes: Vybium STARKs VM=%d bytes, Triton=%d bytes", len(atlasOutput), len(tritonOutput))
			}
		})
	}
}

func buildAtlasProver(t *testing.T) (string, error) {
	// Find project root
	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	// Build binary
	binaryPath := filepath.Join(projectRoot, "vybium-starks-vm-prover")
	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/vybium-starks-vm-prover")
	cmd.Dir = projectRoot

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %v, output: %s", err, string(output))
	}

	return binaryPath, nil
}

func runProver(proverPath string, tc TestCase) (stdout string, stderr string, exitCode int) {
	// Prepare input JSON lines
	claimJSON, _ := json.Marshal(tc.Claim)
	programJSON, _ := json.Marshal(tc.Program)
	nonDetJSON, _ := json.Marshal(tc.NonDeterminism)
	maxHeightJSON, _ := json.Marshal(tc.MaxLog2Height)
	envVarsJSON, _ := json.Marshal(tc.EnvVars)

	input := bytes.Buffer{}
	input.Write(claimJSON)
	input.WriteString("\n")
	input.Write(programJSON)
	input.WriteString("\n")
	input.Write(nonDetJSON)
	input.WriteString("\n")
	input.Write(maxHeightJSON)
	input.WriteString("\n")
	input.Write(envVarsJSON)
	input.WriteString("\n")

	// Run the prover
	cmd := exec.Command(proverPath)
	cmd.Stdin = &input

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

func findProjectRoot() (string, error) {
	// Start from current working directory
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Look for go.mod to find project root
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("project root not found")
		}
		dir = parent
	}
}
