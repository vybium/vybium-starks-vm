package vybiumstarksvm

import "fmt"

// ErrorCode represents a Vybium STARKs VM error code
type ErrorCode int

const (
	// ErrUnknown represents an unknown error
	ErrUnknown ErrorCode = iota

	// ErrInvalidConfig represents an invalid configuration error
	ErrInvalidConfig

	// ErrFieldCreation represents a field creation error
	ErrFieldCreation

	// ErrVMExecution represents a VM execution error
	ErrVMExecution

	// ErrProofGeneration represents a proof generation error
	ErrProofGeneration

	// ErrProofVerification represents a proof verification error
	ErrProofVerification

	// ErrInvalidProof represents an invalid proof error
	ErrInvalidProof

	// ErrNotImplemented represents a not implemented error.
	// NOTE: This error code is defined for completeness but should NOT be used
	// in production code. All features must be fully implemented before release.
	ErrNotImplemented

	// ErrInvalidInput represents an invalid input error
	ErrInvalidInput
)

// VMError represents a Vybium STARKs VM error
type VMError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

// Error returns the error message
func (e *VMError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vybium-starks-vm error [%d]: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("vybium-starks-vm error [%d]: %s", e.Code, e.Message)
}

// Unwrap returns the cause of the error
func (e *VMError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target error
func (e *VMError) Is(target error) bool {
	t, ok := target.(*VMError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}
