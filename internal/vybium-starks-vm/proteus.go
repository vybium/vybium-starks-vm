// Package proteus provides a modern, production-ready implementation of zkSTARKs
// (Zero-Knowledge Scalable Transparent ARguments of Knowledge) in Go.
//
// This package re-exports all functionality from the internal subpackages
// to maintain a clean, unified API while providing proper separation of concerns.
package vybiumstarksvm

import (
	"github.com/vybium/vybium-crypto/pkg/vybium-crypto/field"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/codes"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/core"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/protocols"
	"github.com/vybium/vybium-starks-vm/internal/vybium-starks-vm/utils"
)

// Re-export core types and functions
type (
	Field        = core.Field
	FieldElement = field.Element
	Polynomial   = core.Polynomial
	MerkleTree   = core.MerkleTree
	ProofNode    = core.ProofNode
	Point        = core.Point
)

// Re-export core constructors and functions
var (
	NewField               = core.NewField
	NewFieldFromUint64     = core.NewFieldFromUint64
	NewPolynomial          = core.NewPolynomial
	NewPolynomialFromInt64 = core.NewPolynomialFromInt64
	NewMerkleTree          = core.NewMerkleTree
	NewPoint               = core.NewPoint
	LagrangeInterpolation  = core.LagrangeInterpolation
)

// Re-export protocol types and functions
type (
	FRIProtocol        = protocols.FRIProtocol
	FRIProof           = protocols.FRIProof
	FRILayer           = protocols.FRILayer
	FRIQueryPhase      = protocols.FRIQueryPhase
	QueryResult        = protocols.QueryResult
	QueryTest          = protocols.QueryTest
	Coset              = protocols.Coset
	Subspace           = protocols.Subspace
	DEEPFRIProtocol    = protocols.DEEPFRIProtocol
	DEEPFRIProof       = protocols.DEEPFRIProof
	DEEPFRILayer       = protocols.DEEPFRILayer
	ExternalEvaluation = protocols.ExternalEvaluation
	DEEPALIProtocol    = protocols.DEEPALIProtocol
	DEEPALIProof       = protocols.DEEPALIProof
	APRConstraint      = protocols.APRConstraint
	APRInstance        = protocols.APRInstance
	APRWitness         = protocols.APRWitness
	AIR                = protocols.AIR
	ALI                = protocols.ALI
	ALIProof           = protocols.ALIProof
	ALIQuery           = protocols.ALIQuery
	R1CS               = protocols.R1CS
	R1CSInstance       = protocols.R1CSInstance
	R1CSWitness        = protocols.R1CSWitness
	R1CSProver         = protocols.R1CSProver
	R1CSVerifier       = protocols.R1CSVerifier
	AIRConstraint      = protocols.AIRConstraint
)

// Re-export lookup argument types and functions
type (
	LookupTable      = protocols.LookupTable
	LookupConstraint = protocols.LookupConstraint
	LookupProof      = protocols.LookupProof
	LookupProver     = protocols.LookupProver
	LookupVerifier   = protocols.LookupVerifier
	LookupAIR        = protocols.LookupAIR
)

// Re-export protocol constructors and functions
var (
	NewFRIProtocol         = protocols.NewFRIProtocol
	NewDEEPFRIProtocol     = protocols.NewDEEPFRIProtocol
	NewDEEPALIProtocol     = protocols.NewDEEPALIProtocol
	CreateAPRInstance      = protocols.CreateAPRInstance
	NewAIR                 = protocols.NewAIR
	NewALI                 = protocols.NewALI
	NewR1CS                = protocols.NewR1CS
	NewR1CSProver          = protocols.NewR1CSProver
	NewR1CSVerifier        = protocols.NewR1CSVerifier
	CreateFibonacciR1CS    = protocols.CreateFibonacciR1CS
	CreateFibonacciWitness = protocols.CreateFibonacciWitness
)

// Re-export lookup argument constructors and functions
var (
	NewLookupTable       = protocols.NewLookupTable
	CreateRangeTable     = protocols.CreateRangeTable
	CreateBitTable       = protocols.CreateBitTable
	CreateXORTable       = protocols.CreateXORTable
	NewLookupProver      = protocols.NewLookupProver
	NewLookupVerifier    = protocols.NewLookupVerifier
	NewLookupAIR         = protocols.NewLookupAIR
	RangeCheckConstraint = protocols.RangeCheckConstraint
	BitCheckConstraint   = protocols.BitCheckConstraint
)

// Re-export code types and functions
type (
	ReedSolomonCode      = codes.ReedSolomonCode
	BinaryAdditiveRSCode = codes.BinaryAdditiveRSCode
)

// Re-export code constructors and functions
var (
	NewReedSolomonCode      = codes.NewReedSolomonCode
	NewBinaryAdditiveRSCode = codes.NewBinaryAdditiveRSCode
)

// Re-export utility types and functions
type (
	Config  = utils.Config
	Channel = utils.Channel
)

// Re-export utility constructors and functions
var (
	DefaultConfig  = utils.DefaultConfig
	NewChannel     = utils.NewChannel
	IsPowerOfTwo   = utils.IsPowerOfTwo
	Log2           = utils.Log2
	NextPowerOfTwo = utils.NextPowerOfTwo
)
