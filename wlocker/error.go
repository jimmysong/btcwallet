/*
 * Copyright (c) 2014 The btcsuite developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package waddrmgr

import (
	"fmt"
	"strconv"

	"github.com/btcsuite/btcutil/hdkeychain"
)

var (
	// errAlreadyExists is the common error description used for the
	// ErrAlreadyExists error code.
	errAlreadyExists = "the specified locker already exists"

	// errLocked is the common error description used for the ErrLocked
	// error code.
	errLocked = "locker is locked"
)

// ErrorCode identifies a kind of error.
type ErrorCode int

// These constants are used to identify a specific ManagerError.
const (
	// ErrDatabase indicates an error with the underlying database.  When
	// this error code is set, the Err field of the ManagerError will be
	// set to the underlying error returned from the database.
	ErrDatabase ErrorCode = iota

	// ErrUpgrade indicates the manager needs to be upgraded.  This should
	// not happen in practice unless the version number has been increased
	// and there is not yet any code written to upgrade.
	ErrUpgrade

	// ErrNoExist indicates that the specified database does not exist.
	ErrNoExist

	// ErrAlreadyExists indicates that the specified database already exists.
	ErrAlreadyExists

	// ErrLocked indicates that an operation, which requires the account
	// manager to be unlocked, was requested on a locked account manager.
	ErrLocked

	// ErrWrongPassphrase indicates that the specified passphrase is incorrect.
	// This could be for either public or private master keys.
	ErrWrongPassphrase

	// ErrCallBackBreak is used to break from a callback function passed
	// down to the manager.
	ErrCallBackBreak

	// ErrEmptyPassphrase indicates that the private passphrase was refused
	// due to being empty.
	ErrEmptyPassphrase
)

// Map of ErrorCode values back to their constant names for pretty printing.
var errorCodeStrings = map[ErrorCode]string{
	ErrDatabase:          "ErrDatabase",
	ErrUpgrade:           "ErrUpgrade",
	ErrNoExist:           "ErrNoExist",
	ErrAlreadyExists:     "ErrAlreadyExists",
	ErrLocked:            "ErrLocked",
	ErrWrongPassphrase:   "ErrWrongPassphrase",
	ErrCallBackBreak:     "ErrCallBackBreak",
	ErrEmptyPassphrase:   "ErrEmptyPassphrase",
}

// String returns the ErrorCode as a human-readable name.
func (e ErrorCode) String() string {
	if s := errorCodeStrings[e]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ErrorCode (%d)", int(e))
}

// LockerError provides a single type for errors that can happen during a
// locker operation.  It is used to indicate several types of failures
// including errors with the database (ErrDatabase)
//
// The caller can use type assertions to determine if an error is a LockerError
// and access the ErrorCode field to ascertain the specific reason for the
// failure.
//
// The ErrDatabase error codes will also have the Err field set with the
// underlying error.
type LockerError struct {
	ErrorCode   ErrorCode // Describes the kind of error
	Description string    // Human readable description of the issue
	Err         error     // Underlying error
}

// Error satisfies the error interface and prints human-readable errors.
func (e LockerError) Error() string {
	if e.Err != nil {
		return e.Description + ": " + e.Err.Error()
	}
	return e.Description
}

// lockerError creates a LockerError given a set of arguments.
func lockerError(c ErrorCode, desc string, err error) LockerError {
	return LockerError{ErrorCode: c, Description: desc, Err: err}
}

// Break is a global err used to signal a break from the callback
// function by returning an error with the code ErrCallBackBreak
var Break = lockerError(ErrCallBackBreak, "callback break", nil)

// IsError returns whether the error is a LockerError with a matching error
// code.
func IsError(err error, code ErrorCode) bool {
	e, ok := err.(LockerError)
	return ok && e.ErrorCode == code
}
