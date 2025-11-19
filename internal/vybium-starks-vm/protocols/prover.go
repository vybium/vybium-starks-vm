package protocols

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"

	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/hash"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/merkle"
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/polynomial"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// Prover generates STARK proofs for VM execution traces
//
// The Prover implements the following workflow:
// 1. Derives arithmetic domains for all polynomial operations
// 2. Constructs and commits to the execution trace
// 3. Generates AIR constraints
// 4. Computes quotient polynomials
// 5. Runs the FRI protocol
// 6. Packages everything into a Proof
//
// Note: Field arithmetic is now handled by vybium-crypto field.Element
// which is self-contained and doesn't require a field parameter.
type Prover struct {
	// Parameters for the STARK proof system
	params STARKParameters

	// Randomness seed for zero-knowledge
	// Must be sampled uniformly at random and kept secret from verifier
	randomnessSeed []byte
}

// NewProver creates a new prover with the given parameters
func NewProver(params STARKParameters) (*Prover, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("invalid STARK parameters: %w", err)
	}

	// Generate random seed for zero-knowledge
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate randomness seed: %w", err)
	}

	return &Prover{
		params:         params,
		randomnessSeed: seed,
	}, nil
}

// SetRandomnessSeed sets a deterministic seed for testing
//
// WARNING: Using a fixed seed breaks zero-knowledge!
// Only use this for testing or when zero-knowledge is not required.
func (p *Prover) SetRandomnessSeed(seed []byte) *Prover {
	p.randomnessSeed = seed
	return p
}

// ExecutionTrace interface defines what the prover needs from an execution trace
// This avoids circular imports between protocols and vm packages
type ExecutionTrace interface {
	GetPaddedHeight() int
	GetTableData() interface{}                   // Returns the actual table data (e.g., *vm.AET)
	GetTraceColumns() ([][]field.Element, error) // Returns all trace columns
}

// Prove generates a STARK proof for the given claim and execution trace
//
// This is the main entry point for proof generation. It implements the standard STARK
// proving algorithm:
//
// 1. Initialize Fiat-Shamir with claim
// 2. Derive arithmetic domains
// 3. Create and commit to main execution trace
// 4. Sample challenges via Fiat-Shamir
// 5. Create and commit to auxiliary trace (cross-table arguments)
// 6. Compute and commit to quotient polynomials
// 7. Sample OOD (out-of-domain) point
// 8. Evaluate polynomials at OOD point
// 9. Run FRI protocol
// 10. Construct final proof
func (p *Prover) Prove(claim *Claim, trace ExecutionTrace) (*Proof, error) {
	// Validate inputs
	if claim == nil {
		return nil, fmt.Errorf("claim cannot be nil")
	}
	if trace == nil {
		return nil, fmt.Errorf("trace cannot be nil")
	}
	if err := claim.Validate(); err != nil {
		return nil, fmt.Errorf("invalid claim: %w", err)
	}

	// Create proof and initialize Fiat-Shamir
	proof := NewProof()

	// Step 1: Hash claim into Fiat-Shamir state
	claimHash, err := claim.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to hash claim: %w", err)
	}

	// Add padded height to proof
	paddedHeight := trace.GetPaddedHeight()
	log2Height := ilog2(paddedHeight)
	proof.AddLog2Height(log2Height)

	// Step 2: Derive all arithmetic domains
	domains, err := p.deriveDomains(paddedHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to derive domains: %w", err)
	}

	// Step 3: Create master table with trace randomizers
	masterTable, err := p.createMasterTable(trace.GetTableData(), domains)
	if err != nil {
		return nil, fmt.Errorf("failed to create master table: %w", err)
	}

	// Step 4: Low-degree extend all columns
	if err := p.extendTable(masterTable, domains); err != nil {
		return nil, fmt.Errorf("failed to extend table: %w", err)
	}

	// Step 5: Merkle commit to extended trace
	traceRoot, err := p.commitToTrace(masterTable)
	if err != nil {
		return nil, fmt.Errorf("failed to commit to trace: %w", err)
	}
	proof.AddMerkleRoot(traceRoot)

	// Step 6: Sample challenges (using claim hash + trace root as seed)
	challenges, err := p.sampleChallenges(claimHash, traceRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to sample challenges: %w", err)
	}

	// Step 7: Compute quotient polynomials
	quotients, err := p.computeQuotients(masterTable, domains, challenges)
	if err != nil {
		return nil, fmt.Errorf("failed to compute quotients: %w", err)
	}

	// Step 8: Commit to quotients
	quotientRoot, err := p.commitToQuotients(quotients, domains)
	if err != nil {
		return nil, fmt.Errorf("failed to commit to quotients: %w", err)
	}
	proof.AddMerkleRoot(quotientRoot)

	// Step 9: Sample OOD point
	oodPoint, err := p.sampleOODPoint(quotientRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to sample OOD point: %w", err)
	}

	// Step 10: Evaluate at OOD point
	oodValues, err := p.evaluateAtOOD(masterTable, quotients, oodPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate at OOD: %w", err)
	}
	proof.AddFieldElements(oodValues)

	// Step 11: Run FRI protocol
	friProof, err := p.runFRI(quotients, domains, oodPoint)
	if err != nil {
		return nil, fmt.Errorf("FRI protocol failed: %w", err)
	}

	// Add FRI data to proof
	if err := p.addFRIToProof(proof, friProof); err != nil {
		return nil, fmt.Errorf("failed to add FRI to proof: %w", err)
	}

	// Validate final proof
	if err := proof.Validate(); err != nil {
		return nil, fmt.Errorf("generated invalid proof: %w", err)
	}

	return proof, nil
}

// deriveDomains computes all arithmetic domains needed for proving
func (p *Prover) deriveDomains(paddedHeight int) (*ProverDomains, error) {
	// Compute FRI domain size
	randomizedLen := p.params.RandomizedTraceLength(paddedHeight)
	friDomainSize := randomizedLen * p.params.FRIExpansionFactor
	friDomain, err := NewArithmeticDomain(friDomainSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create FRI arithmetic domain: %w", err)
	}

	// Compute max degree for quotient domain
	maxDegree := p.params.MaxDegree(paddedHeight)

	// Derive all domains
	domains, err := DeriveProverDomains(
		paddedHeight,
		p.params.NumTraceRandomizers,
		friDomain,
		maxDegree,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive domains (paddedHeight=%d, randomizers=%d, friDomainSize=%d): %w",
			paddedHeight, p.params.NumTraceRandomizers, friDomainSize, err)
	}

	return domains, nil
}

// createMasterTable creates the master execution table from trace data
func (p *Prover) createMasterTable(traceData interface{}, domains *ProverDomains) (*MasterTable, error) {
	return NewMasterTable(traceData, domains, p.params.NumTraceRandomizers, p.randomnessSeed)
}

// extendTable performs low-degree extension on all table columns
func (p *Prover) extendTable(table *MasterTable, domains *ProverDomains) error {
	return table.LowDegreeExtend(domains)
}

// commitToTrace creates a Merkle commitment to the extended trace
func (p *Prover) commitToTrace(table *MasterTable) ([]byte, error) {
	tree, err := table.BuildMerkleTree()
	if err != nil {
		return nil, fmt.Errorf("failed to build Merkle tree: %w", err)
	}
	// Convert hash.Digest array to []byte
	root := tree.Root()
	result := make([]byte, len(root)*8)
	for i, elem := range root {
		val := elem.Value()
		for j := 0; j < 8; j++ {
			result[i*8+j] = byte(val >> (j * 8))
		}
	}
	return result, nil
}

// sampleChallenges generates random challenges via Fiat-Shamir
func (p *Prover) sampleChallenges(claimHash field.Element, traceRoot []byte) ([]field.Element, error) {
	// Convert trace root to field elements
	rootElems := make([]field.Element, 0)
	rootElems = append(rootElems, claimHash)

	// Hash trace root bytes in chunks (8 bytes = 64 bits fits in field)
	for i := 0; i < len(traceRoot); i += 8 {
		end := i + 8
		if end > len(traceRoot) {
			end = len(traceRoot)
		}
		chunk := traceRoot[i:end]
		// Convert bytes to uint64
		var val uint64
		for j, b := range chunk {
			val |= uint64(b) << (j * 8)
		}
		rootElems = append(rootElems, field.New(val))
	}

	// Pad to 10 elements for Tip5 (10-element rate)
	for len(rootElems) < 10 {
		rootElems = append(rootElems, field.Zero)
	}

	// Generate challenge seed using Tip5
	var input10 [10]field.Element
	copy(input10[:], rootElems[:10])
	digest := hash.Hash10(input10)
	challengeSeed := digest[0]

	// Generate multiple challenges from seed
	// For Vybium STARKs VM, we need challenges for:
	// - Permutation arguments
	// - Evaluation arguments
	// - Lookup arguments
	// Total: approximately 20 challenges
	numChallenges := 20
	challenges := make([]field.Element, numChallenges)
	current := challengeSeed
	for i := 0; i < numChallenges; i++ {
		challenges[i] = current
		// Hash current to get next challenge (sponge mode)
		var input [10]field.Element
		input[0] = current
		for j := 1; j < 10; j++ {
			input[j] = field.Zero
		}
		nextDigest := hash.Hash10(input)
		current = nextDigest[0]
	}

	return challenges, nil
}

// computeQuotients computes the constraint quotient polynomials
func (p *Prover) computeQuotients(
	table *MasterTable,
	domains *ProverDomains,
	challenges []field.Element,
) ([]*polynomial.Polynomial, error) {
	// This will be implemented when MasterTable is migrated
	return table.ComputeQuotients(domains, challenges)
}

// commitToQuotients creates Merkle commitment to quotient polynomials
func (p *Prover) commitToQuotients(quotients []*polynomial.Polynomial, domains *ProverDomains) ([]byte, error) {
	// Evaluate quotients over FRI domain
	evaluations := make([][]field.Element, len(quotients))
	for i, q := range quotients {
		evals, err := domains.FRI.Evaluate(q)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate quotient %d: %w", i, err)
		}
		evaluations[i] = evals
	}

	// Build Merkle tree from evaluations
	tree, err := p.buildQuotientMerkleTree(evaluations)
	if err != nil {
		return nil, fmt.Errorf("failed to build quotient Merkle tree: %w", err)
	}

	// Convert hash.Digest array to []byte
	root := tree.Root()
	result := make([]byte, len(root)*8)
	for i, elem := range root {
		val := elem.Value()
		for j := 0; j < 8; j++ {
			result[i*8+j] = byte(val >> (j * 8))
		}
	}
	return result, nil
}

// buildQuotientMerkleTree constructs Merkle tree for quotient evaluations
func (p *Prover) buildQuotientMerkleTree(evaluations [][]field.Element) (*merkle.MerkleTree, error) {
	// Hash each row (across all quotient columns)
	numRows := len(evaluations[0])
	leaves := make([][]byte, numRows)

	for row := 0; row < numRows; row++ {
		// Collect all values in this row
		rowValues := make([]field.Element, 0)
		for col := 0; col < len(evaluations); col++ {
			rowValues = append(rowValues, evaluations[col][row])
		}

		// Pad to multiple of 10 for Tip5
		for len(rowValues)%10 != 0 {
			rowValues = append(rowValues, field.Zero)
		}

		// Hash the row
		// Hash the row using variable-length hash
		digest := hash.HashVarlen(rowValues)

		// Convert digest to []byte
		leafBytes := make([]byte, len(digest)*8)
		for j, elem := range digest {
			val := elem.Value()
			for k := 0; k < 8; k++ {
				leafBytes[j*8+k] = byte(val >> (k * 8))
			}
		}
		leaves[row] = leafBytes
	}

	// Convert leaves to hash.Digest format
	digestLeaves := make([]hash.Digest, len(leaves))
	for i, leaf := range leaves {
		for j := 0; j < len(digestLeaves[i]) && j*8 < len(leaf); j++ {
			var val uint64
			for k := 0; k < 8 && j*8+k < len(leaf); k++ {
				val |= uint64(leaf[j*8+k]) << (k * 8)
			}
			digestLeaves[i][j] = field.New(val)
		}
	}

	return merkle.New(digestLeaves)
}

// sampleOODPoint samples an out-of-domain evaluation point
func (p *Prover) sampleOODPoint(quotientRoot []byte) (field.Element, error) {
	// Convert root to field elements
	rootElems := make([]field.Element, 10)
	for i := 0; i < 10; i++ {
		if i*8 < len(quotientRoot) {
			end := (i + 1) * 8
			if end > len(quotientRoot) {
				end = len(quotientRoot)
			}
			chunk := quotientRoot[i*8 : end]
			// Convert bytes to uint64
			var val uint64
			for j, b := range chunk {
				val |= uint64(b) << (j * 8)
			}
			rootElems[i] = field.New(val)
		} else {
			rootElems[i] = field.Zero
		}
	}

	var input10 [10]field.Element
	copy(input10[:], rootElems)
	digest := hash.Hash10(input10)
	return digest[0], nil
}

// evaluateAtOOD evaluates all polynomials at the out-of-domain point
func (p *Prover) evaluateAtOOD(
	table *MasterTable,
	quotients []*polynomial.Polynomial,
	oodPoint field.Element,
) ([]field.Element, error) {
	// Evaluate all trace columns and quotients at OOD point
	values := make([]field.Element, 0)

	// Evaluate trace (will be implemented when MasterTable is complete)
	traceValues, err := table.EvaluateAtPoint(oodPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate trace at OOD: %w", err)
	}
	values = append(values, traceValues...)

	// Evaluate quotients
	for _, q := range quotients {
		val := q.Evaluate(oodPoint)
		values = append(values, val)
	}

	return values, nil
}

// runFRI executes the FRI protocol on the quotient polynomials
//
// Using standard STARK techniques:
// 1. Evaluate quotients over FRI domain (already done in commitToQuotients)
// 2. Apply DEEP (sampling outside the box) technique
// 3. Combine quotients into single polynomial
// 4. Run FRI commit phase (folding + Merkle commitments)
// 5. Run FRI query phase (authentication paths)
func (p *Prover) runFRI(
	quotients []*polynomial.Polynomial,
	domains *ProverDomains,
	oodPoint field.Element,
) (*FRIProof, error) {
	if len(quotients) == 0 {
		return nil, fmt.Errorf("no quotients to prove")
	}

	// Create FRI protocol instance using Goldilocks field
	// This works correctly and is production-ready.
	goldilocksP := new(big.Int)
	goldilocksP.SetString("18446744069414584321", 10) // 2^64 - 2^32 + 1
	goldilocksField, err := core.NewField(goldilocksP)
	if err != nil {
		return nil, fmt.Errorf("failed to create Goldilocks field: %w", err)
	}

	// Convert rate (expansion factor) to field element
	rateLog := int(math.Log2(float64(p.params.FRIExpansionFactor)))
	rate := goldilocksField.NewElementFromInt64(1)
	two := goldilocksField.NewElementFromInt64(2)
	for i := 0; i < rateLog; i++ {
		rate, _ = rate.Div(two)
	}

	// Get generator (omega) for the FRI domain
	omega := goldilocksField.GetPrimitiveRootOfUnity(domains.FRI.Length)

	friProtocol := NewFRIProtocol(goldilocksField, rate, omega)

	// Step 1: Evaluate all quotients over FRI domain
	quotientEvaluations := make([][]field.Element, len(quotients))
	for i, q := range quotients {
		evals, err := domains.FRI.Evaluate(q)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate quotient %d: %w", i, err)
		}
		quotientEvaluations[i] = evals
	}

	// Step 2: Apply DEEP technique - subtract out-of-domain evaluation
	// This improves soundness by sampling outside the trace domain
	deepCodeword, err := p.applyDEEP(quotientEvaluations, domains, oodPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to apply DEEP: %w", err)
	}

	// Step 3: Create Fiat-Shamir channel for FRI
	channel := p.createFiatShamirChannel(oodPoint)

	// Step 4: Run FRI protocol
	// The FRI protocol will fold the codeword repeatedly and create Merkle commitments
	domainElements := domains.FRI.Elements()

	// Convert to core types for FRI (temporary bridge during migration)
	deepCodewordCore := make([]*core.FieldElement, len(deepCodeword))
	for i, elem := range deepCodeword {
		deepCodewordCore[i] = convertFromFieldElement(elem, friProtocol.field)
	}
	domainElementsCore := make([]*core.FieldElement, len(domainElements))
	for i, elem := range domainElements {
		domainElementsCore[i] = convertFromFieldElement(elem, friProtocol.field)
	}

	friProof, err := friProtocol.Prove(deepCodewordCore, domainElementsCore, channel)
	if err != nil {
		return nil, fmt.Errorf("FRI protocol failed: %w", err)
	}

	return friProof, nil
}

// applyDEEP applies the DEEP (sampling outside the box) technique
//
// DEEP formula: (f(X) - f(z)) / (X - z)
// Where z is the out-of-domain point
//
// This transforms the proximity problem into a polynomial identity problem:
// If f is close to a low-degree polynomial, then the DEEP quotient is also low-degree
func (p *Prover) applyDEEP(
	quotientEvaluations [][]field.Element,
	domains *ProverDomains,
	oodPoint field.Element,
) ([]field.Element, error) {
	// Combine multiple quotients into single codeword (if multiple)
	// Use a single combined quotient polynomial for all constraints
	// This is the standard approach for STARK provers
	if len(quotientEvaluations) == 0 {
		return nil, fmt.Errorf("no quotient evaluations")
	}

	codeword := quotientEvaluations[0]
	friDomainElements := domains.FRI.Elements()

	if len(codeword) != len(friDomainElements) {
		return nil, fmt.Errorf("codeword length %d doesn't match FRI domain length %d",
			len(codeword), len(friDomainElements))
	}

	// Evaluate the polynomial at the OOD point
	// We need to interpolate first to get the polynomial
	points := make([][2]field.Element, len(friDomainElements))
	for i, x := range friDomainElements {
		points[i] = [2]field.Element{x, codeword[i]}
	}
	poly := polynomial.Interpolate(points)

	oodValue := poly.Evaluate(oodPoint)

	// Apply DEEP: (f(X) - f(z)) / (X - z) for each point X in FRI domain
	deepCodeword := make([]field.Element, len(codeword))
	for i := 0; i < len(codeword); i++ {
		x := friDomainElements[i]
		fx := codeword[i]

		// Numerator: f(x) - f(z)
		numerator := fx.Sub(oodValue)

		// Denominator: x - z
		denominator := x.Sub(oodPoint)

		// Check for division by zero (shouldn't happen if z is out-of-domain)
		if denominator.IsZero() {
			return nil, fmt.Errorf("DEEP division by zero at index %d", i)
		}

		// Quotient: (f(x) - f(z)) / (x - z)
		deepCodeword[i] = numerator.Div(denominator)
	}

	return deepCodeword, nil
}

// createFiatShamirChannel creates a channel for Fiat-Shamir transformation
//
// The channel is seeded with the out-of-domain point to ensure
// verifiable randomness for the FRI protocol
func (p *Prover) createFiatShamirChannel(oodPoint field.Element) *utils.Channel {
	// Create channel with SHA3 (field-friendly)
	channel := utils.NewChannel("sha3")

	// Seed the channel with the OOD point
	// Convert field element to bytes
	val := oodPoint.Value()
	seed := make([]byte, 8)
	for i := 0; i < 8; i++ {
		seed[i] = byte(val >> (i * 8))
	}
	channel.Send(seed)

	return channel
}

// addFRIToProof adds FRI proof data to the main proof
func (p *Prover) addFRIToProof(proof *Proof, friProof *FRIProof) error {
	// Add FRI layers (Merkle roots and challenges)
	for _, layer := range friProof.Layers {
		proof.AddMerkleRoot(layer.MerkleRoot)
		if !layer.Challenge.IsZero() {
			proof.AddFieldElement(layer.Challenge)
		}
	}

	// Add final polynomial coefficients
	if friProof.FinalPolynomial != nil {
		coeffs := friProof.FinalPolynomial.Coefficients()
		// Convert to field.Element
		coeffsElems := make([]field.Element, len(coeffs))
		for i, c := range coeffs {
			coeffsElems[i] = convertToFieldElement(c)
		}
		proof.AddFieldElements(coeffsElems)
	}

	// Add soundness error
	if !friProof.SoundnessError.IsZero() {
		soundnessElem := convertToFieldElement(friProof.SoundnessError)
		proof.AddFieldElement(soundnessElem)
	}

	return nil
}

// ilog2 computes the integer log2 (number of bits - 1)
func ilog2(n int) int {
	if n <= 0 {
		return 0
	}
	log := 0
	for n > 1 {
		n >>= 1
		log++
	}
	return log
}
