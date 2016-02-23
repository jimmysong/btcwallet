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
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/wlocker"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0x2a, 0x64, 0xdf, 0x08, 0x5e, 0xef, 0xed, 0xd8, 0xbf,
		0xdb, 0xb3, 0x31, 0x76, 0xb5, 0xba, 0x2e, 0x62, 0xe8,
		0xbe, 0x8b, 0x56, 0xc8, 0x83, 0x77, 0x95, 0x59, 0x8b,
		0xb6, 0xc4, 0x40, 0xc0, 0x64,
	}

	pubPassphrase   = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase  = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")
	pubPassphrase2  = []byte("-0NV4P~VSJBWbunw}%<Z]fuGpbN[ZI")
	privPassphrase2 = []byte("~{<]08%6!-?2s<$(8$8:f(5[4/!/{Y")

	// fastScrypt are parameters used throughout the tests to speed up the
	// scrypt operations.
	fastScrypt = &wlocker.ScryptOptions{
		N: 16,
		R: 8,
		P: 1,
	}

	// wlockerNamespaceKey is the namespace key for the wlocker package.
	wlockerNamespaceKey = []byte("wlockerNamespace")

)

// checkLockerError ensures the passed error is a LockerError with an error
// code that matches the passed  error code.
func checkLockerError(t *testing.T, testName string, gotErr error, wantErrCode wlocker.ErrorCode) bool {
	merr, ok := gotErr.(wlocker.LockerError)
	if !ok {
		t.Errorf("%s: unexpected error type - got %T, want %T",
			testName, gotErr, wlocker.LockerError{})
		return false
	}
	if merr.ErrorCode != wantErrCode {
		t.Errorf("%s: unexpected error code - got %s (%s), want %s",
			testName, merr.ErrorCode, merr.Description, wantErrCode)
		return false
	}

	return true
}

// hexToBytes is a wrapper around hex.DecodeString that panics if there is an
// error.  It MUST only be used with hard coded values in the tests.
func hexToBytes(origHex string) []byte {
	buf, err := hex.DecodeString(origHex)
	if err != nil {
		panic(err)
	}
	return buf
}

// createDbNamespace creates a new wallet database at the provided path and
// returns it along with the address locker namespace.
func createDbNamespace(dbPath string) (walletdb.DB, walletdb.Namespace, error) {
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, nil, err
	}

	namespace, err := db.Namespace(wlockerNamespaceKey)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return db, namespace, nil
}

// openDbNamespace opens wallet database at the provided path and returns it
// along with the address locker namespace.
func openDbNamespace(dbPath string) (walletdb.DB, walletdb.Namespace, error) {
	db, err := walletdb.Open("bdb", dbPath)
	if err != nil {
		return nil, nil, err
	}

	namespace, err := db.Namespace(wlockerNamespaceKey)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return db, namespace, nil
}

// setupLocker creates a new address locker and returns a teardown function
// that should be invoked to ensure it is closed and removed upon completion.
func setupLocker(t *testing.T) (tearDownFunc func(), mgr *wlocker.Locker) {
	t.Parallel()

	// Create a new locker in a temp directory.
	dirName, err := ioutil.TempDir("", "mgrtest")
	if err != nil {
		t.Fatalf("Failed to create db temp dir: %v", err)
	}
	dbPath := filepath.Join(dirName, "mgrtest.db")
	db, namespace, err := createDbNamespace(dbPath)
	if err != nil {
		_ = os.RemoveAll(dirName)
		t.Fatalf("createDbNamespace: unexpected error: %v", err)
	}
	mgr, err = wlocker.Create(namespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if err != nil {
		db.Close()
		_ = os.RemoveAll(dirName)
		t.Fatalf("Failed to create Locker: %v", err)
	}
	tearDownFunc = func() {
		mgr.Close()
		db.Close()
		_ = os.RemoveAll(dirName)
	}
	return tearDownFunc, mgr
}
