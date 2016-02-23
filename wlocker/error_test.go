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

package wlocker_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/wlocker"
)

// TestErrorCodeStringer tests the stringized output for the ErrorCode type.
func TestErrorCodeStringer(t *testing.T) {
	tests := []struct {
		in   wlocker.ErrorCode
		want string
	}{
		{wlocker.ErrDatabase, "ErrDatabase"},
		{wlocker.ErrUpgrade, "ErrUpgrade"},
		{wlocker.ErrCrypto, "ErrCrypto"},
		{wlocker.ErrInvalidKeyType, "ErrInvalidKeyType"},
		{wlocker.ErrNoExist, "ErrNoExist"},
		{wlocker.ErrAlreadyExists, "ErrAlreadyExists"},
		{wlocker.ErrLocked, "ErrLocked"},
		{wlocker.ErrWrongPassphrase, "ErrWrongPassphrase"},
		{wlocker.ErrCallBackBreak, "ErrCallBackBreak"},
		{wlocker.ErrEmptyPassphrase, "ErrEmptyPassphrase"},
		{0xffff, "Unknown ErrorCode (65535)"},
	}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\ngot: %s\nwant: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestLockerError tests the error output for the LockerError type.
func TestLockerError(t *testing.T) {
	tests := []struct {
		in   wlocker.LockerError
		want string
	}{
		// Locker level error.
		{
			wlocker.LockerError{Description: "human-readable error"},
			"human-readable error",
		},

		// Encapsulated database error.
		{
			wlocker.LockerError{
				Description: "failed to store master private " +
					"key parameters",
				ErrorCode: wlocker.ErrDatabase,
				Err:       fmt.Errorf("underlying db error"),
			},
			"failed to store master private key parameters: " +
				"underlying db error",
		},

		// Encapsulated crypto error.
		{
			wlocker.LockerError{
				Description: "failed to decrypt account 0 " +
					"private key",
				ErrorCode: wlocker.ErrCrypto,
				Err:       fmt.Errorf("underlying error"),
			},
			"failed to decrypt account 0 private key: underlying " +
				"error",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("Error #%d\ngot: %s\nwant: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestIsError tests the IsError func.
func TestIsError(t *testing.T) {
	tests := []struct {
		err  error
		code wlocker.ErrorCode
		exp  bool
	}{
		{
			err: wlocker.LockerError{
				ErrorCode: wlocker.ErrDatabase,
			},
			code: wlocker.ErrDatabase,
			exp:  true,
		},
		{
			// package should never return *LockerError
			err: &wlocker.LockerError{
				ErrorCode: wlocker.ErrDatabase,
			},
			code: wlocker.ErrDatabase,
			exp:  false,
		},
		{
			err: wlocker.LockerError{
				ErrorCode: wlocker.ErrCrypto,
			},
			code: wlocker.ErrDatabase,
			exp:  false,
		},
		{
			err:  errors.New("not a LockerError"),
			code: wlocker.ErrDatabase,
			exp:  false,
		},
	}

	for i, test := range tests {
		got := wlocker.IsError(test.err, test.code)
		if got != test.exp {
			t.Errorf("Test %d: got %v expected %v", i, got, test.exp)
		}
	}
}
