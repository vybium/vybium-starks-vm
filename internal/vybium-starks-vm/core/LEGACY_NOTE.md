# Legacy Core Package

⚠️ **This package is being phased out in favor of vybium-crypto**

## Status

This package contains legacy field arithmetic and polynomial operations that are being migrated to `vybium-crypto`. The migration is tracked as technical debt (see TODO-2).

## Panic Statements

The `panic()` calls in this package are **intentional** for the following reasons:

1. **Field Mismatch Errors**: Operations like `Add`, `Sub`, `Mul` panic when mixing elements from different fields (e.g., adding an element from F_p to an element from F_q). This is a **programmer error**, not a runtime error, and should be caught during development.

2. **Polynomial Evaluation**: Panics when evaluating a polynomial at a point from a different field. Again, this is a bug that should be fixed in code, not handled at runtime.

## Why Panics Are Appropriate Here

These are **defensive programming checks** similar to:

- Rust's `panic!` for invariant violations
- C++'s `assert()` in debug mode
- Python's `AssertionError`

If these conditions occur, it indicates a bug in the calling code that must be fixed.

## Migration Path

As we complete the FRI migration (TODO-2), usage of this package will decrease and eventually be eliminated. New code should use:

- `github.com/vybium/vybium-crypto/pkg/vybium-crypto/field` for field operations
- Proper error returns for all user-facing operations

## Adapter Bridge

For code that needs to bridge between legacy `core.Field` and new `field.Element`, use:

- `internal/proteus/adapter/field_adapter.go`

This provides conversion functions while maintaining type safety.
