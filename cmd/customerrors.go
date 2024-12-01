// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - custom error functionality
// These functions are used to return custom errors for certain situations,
// and also defines some return values for final application output.

package main

// Application return values
const (
	Success = iota
	JSONReadError
	NoExfilFile
	NoTargetsFile
	NoCommands
	FileReadError
	NoBouncer
	NoOOBDomain
	TaskMisMatch
	TimerFailure
	InvalidTriggerTarget
	InvalidInputFormat
)

// Returns a custom error with the provided text input
func NewError(text string) error {
	return &errorString{text}
}

// Trivial implementation of error - possible further customisation later
type errorString struct {
	Description string
}

// Return Error Text fo user-defined error
func (errString *errorString) Error() string {
	return errString.Description
}
