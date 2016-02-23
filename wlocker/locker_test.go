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
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wlocker"
	"github.com/btcsuite/btcwallet/walletdb"
)

// newShaHash converts the passed big-endian hex string into a wire.ShaHash.
// It only differs from the one available in wire in that it panics on an
// error since it will only (and must only) be called with hard-coded, and
// therefore known good, hashes.
func newShaHash(hexStr string) *wire.ShaHash {
	sha, err := wire.NewShaHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return sha
}

// testContext is used to store context information about a running test which
// is passed into helper functions.  The useSpends field indicates whether or
// not the spend data should be empty or figure it out based on the specific
// test blocks provided.  This is needed because the first loop where the blocks
// are inserted, the tests are running against the latest block and therefore
// none of the outputs can be spent yet.  However, on subsequent runs, all
// blocks have been inserted and therefore some of the transaction outputs are
// spent.
type testContext struct {
	t            *testing.T
	db           walletdb.DB
	locker      *wlocker.Locker
	account      uint32
	create       bool
	unlocked     bool
}

// addrType is the type of address being tested
type addrType byte

const (
	addrPubKeyHash addrType = iota
	addrScriptHash
)

// testNamePrefix is a helper to return a prefix to show for test errors based
// on the state of the test context.
func testNamePrefix(tc *testContext) string {
	prefix := "Open "
	if tc.create {
		prefix = "Create "
	}

	return prefix + fmt.Sprintf("account #%d", tc.account)
}


// testLocking tests the basic locking semantics of the address locker work
// as expected.  Other tests ensure addresses behave as expected under locked
// and unlocked conditions.
func testLocking(tc *testContext) bool {
	if tc.unlocked {
		tc.t.Error("testLocking called with an unlocked locker")
		return false
	}
	if !tc.locker.IsLocked() {
		tc.t.Error("IsLocked: returned false on locked locker")
		return false
	}

	// Locking an already lock locker should return an error.  The error
	// should be ErrLocked or ErrWatchingOnly depending on the type of the
	// address locker.
	err := tc.locker.Lock()
	wantErrCode := wlocker.ErrLocked
	if !checkLockerError(tc.t, "Lock", err, wantErrCode) {
		return false
	}

	// Ensure unlocking with the correct passphrase doesn't return any
	// unexpected errors and the locker properly reports it is unlocked.
	// Since watching-only address lockers can't be unlocked, also ensure
	// the correct error for that case.
	err = tc.locker.Unlock(privPassphrase)
	if err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	if tc.locker.IsLocked() {
		tc.t.Error("IsLocked: returned true on unlocked locker")
		return false
	}

	// Unlocking the locker again is allowed.  Since watching-only address
	// lockers can't be unlocked, also ensure the correct error for that
	// case.
	err = tc.locker.Unlock(privPassphrase)
	if err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	if tc.locker.IsLocked() {
		tc.t.Error("IsLocked: returned true on unlocked locker")
		return false
	}

	// Unlocking the locker with an invalid passphrase must result in an
	// error and a locked locker.
	err = tc.locker.Unlock([]byte("invalidpassphrase"))
	wantErrCode = wlocker.ErrWrongPassphrase
	if !checkLockerError(tc.t, "Unlock", err, wantErrCode) {
		return false
	}
	if !tc.locker.IsLocked() {
		tc.t.Error("IsLocked: locker is unlocked after failed unlock " +
			"attempt")
		return false
	}

	return true
}

// testChangePassphrase ensures changes both the public and privte passphrases
// works as intended.
func testChangePassphrase(tc *testContext) bool {
	// Force an error when changing the passphrase due to failure to
	// generate a new secret key by replacing the generation function one
	// that intentionally errors.
	testName := "ChangePassphrase (public) with invalid new secret key"

	var err error
	wlocker.TstRunWithReplacedNewSecretKey(func() {
		err = tc.locker.ChangePassphrase(pubPassphrase, pubPassphrase2, false, fastScrypt)
	})
	if !checkLockerError(tc.t, testName, err, wlocker.ErrCrypto) {
		return false
	}

	// Attempt to change public passphrase with invalid old passphrase.
	testName = "ChangePassphrase (public) with invalid old passphrase"
	err = tc.locker.ChangePassphrase([]byte("bogus"), pubPassphrase2, false, fastScrypt)
	if !checkLockerError(tc.t, testName, err, wlocker.ErrWrongPassphrase) {
		return false
	}

	// Change the public passphrase.
	testName = "ChangePassphrase (public)"
	err = tc.locker.ChangePassphrase(pubPassphrase, pubPassphrase2, false, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Ensure the public passphrase was successfully changed.
	if !tc.locker.TstCheckPublicPassphrase(pubPassphrase2) {
		tc.t.Errorf("%s: passphrase does not match", testName)
		return false
	}

	// Change the private passphrase back to what it was.
	err = tc.locker.ChangePassphrase(pubPassphrase2, pubPassphrase, false, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Attempt to change private passphrase with invalid old passphrase.
	// The error should be ErrWrongPassphrase or ErrWatchingOnly depending
	// on the type of the address locker.
	testName = "ChangePassphrase (private) with invalid old passphrase"
	err = tc.locker.ChangePassphrase([]byte("bogus"), privPassphrase2, true, fastScrypt)
	wantErrCode := wlocker.ErrWrongPassphrase
	if !checkLockerError(tc.t, testName, err, wantErrCode) {
		return false
	}

	// Change the private passphrase.
	testName = "ChangePassphrase (private)"
	err = tc.locker.ChangePassphrase(privPassphrase, privPassphrase2, true, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Unlock the locker with the new passphrase to ensure it changed as
	// expected.
	if err := tc.locker.Unlock(privPassphrase2); err != nil {
		tc.t.Errorf("%s: failed to unlock with new private "+
			"passphrase: %v", testName, err)
		return false
	}
	tc.unlocked = true

	// Change the private passphrase back to what it was while the locker
	// is unlocked to ensure that path works properly as well.
	err = tc.locker.ChangePassphrase(privPassphrase2, privPassphrase, true, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}
	if tc.locker.IsLocked() {
		tc.t.Errorf("%s: locker is locked", testName)
		return false
	}

	// Relock the locker for future tests.
	if err := tc.locker.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false

	return true
}

// testLockerAPI tests the functions provided by the Locker API as well as
// the ManagedAddress, ManagedPubKeyAddress, and ManagedScriptAddress
// interfaces.
func testLockerAPI(tc *testContext) {
	testLocking(tc)
	testChangePassphrase(tc)
}

// testSync tests various facets of setting the locker sync state.
func testSync(tc *testContext) bool {
	tests := []struct {
		name string
		hash *wire.ShaHash
	}{
		{
			name: "Block 1",
			hash: newShaHash("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"),
		},
		{
			name: "Block 2",
			hash: newShaHash("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"),
		},
		{
			name: "Block 3",
			hash: newShaHash("0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449"),
		},
		{
			name: "Block 4",
			hash: newShaHash("000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485"),
		},
		{
			name: "Block 5",
			hash: newShaHash("000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc"),
		},
		{
			name: "Block 6",
			hash: newShaHash("000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d"),
		},
		{
			name: "Block 7",
			hash: newShaHash("0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444"),
		},
		{
			name: "Block 8",
			hash: newShaHash("00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6"),
		},
		{
			name: "Block 9",
			hash: newShaHash("000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805"),
		},
		{
			name: "Block 10",
			hash: newShaHash("000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9"),
		},
		{
			name: "Block 11",
			hash: newShaHash("0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073"),
		},
		{
			name: "Block 12",
			hash: newShaHash("0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e"),
		},
		{
			name: "Block 13",
			hash: newShaHash("000000005c51de2031a895adc145ee2242e919a01c6d61fb222a54a54b4d3089"),
		},
		{
			name: "Block 14",
			hash: newShaHash("0000000080f17a0c5a67f663a9bc9969eb37e81666d9321125f0e293656f8a37"),
		},
		{
			name: "Block 15",
			hash: newShaHash("00000000b3322c8c3ef7d2cf6da009a776e6a99ee65ec5a32f3f345712238473"),
		},
		{
			name: "Block 16",
			hash: newShaHash("00000000174a25bb399b009cc8deff1c4b3ea84df7e93affaaf60dc3416cc4f5"),
		},
		{
			name: "Block 17",
			hash: newShaHash("000000003ff1d0d70147acfbef5d6a87460ff5bcfce807c2d5b6f0a66bfdf809"),
		},
		{
			name: "Block 18",
			hash: newShaHash("000000008693e98cf893e4c85a446b410bb4dfa129bd1be582c09ed3f0261116"),
		},
		{
			name: "Block 19",
			hash: newShaHash("00000000841cb802ca97cf20fb9470480cae9e5daa5d06b4a18ae2d5dd7f186f"),
		},
		{
			name: "Block 20",
			hash: newShaHash("0000000067a97a2a37b8f190a17f0221e9c3f4fa824ddffdc2e205eae834c8d7"),
		},
		{
			name: "Block 21",
			hash: newShaHash("000000006f016342d1275be946166cff975c8b27542de70a7113ac6d1ef3294f"),
		},
	}

	// Ensure there are enough test vectors to prove the maximum number of
	// recent hashes is working properly.
	maxRecentHashes := wlocker.TstMaxRecentHashes
	if len(tests) < maxRecentHashes-1 {
		tc.t.Errorf("Not enough hashes to test max recent hashes - "+
			"need %d, have %d", maxRecentHashes-1, len(tests))
		return false
	}

	for i, test := range tests {
		blockStamp := wlocker.BlockStamp{
			Height: int32(i) + 1,
			Hash:   *test.hash,
		}
		if err := tc.locker.SetSyncedTo(&blockStamp); err != nil {
			tc.t.Errorf("SetSyncedTo unexpected err: %v", err)
			return false
		}

		// Ensure the locker now claims it is synced to the block stamp
		// that was just set.
		gotBlockStamp := tc.locker.SyncedTo()
		if gotBlockStamp != blockStamp {
			tc.t.Errorf("SyncedTo unexpected block stamp -- got "+
				"%v, want %v", gotBlockStamp, blockStamp)
			return false
		}

		// Ensure the recent blocks iterator works properly.
		j := 0
		iter := tc.locker.NewIterateRecentBlocks()
		for cont := iter != nil; cont; cont = iter.Prev() {
			wantHeight := int32(i) - int32(j) + 1
			var wantHash *wire.ShaHash
			if wantHeight == 0 {
				wantHash = chaincfg.MainNetParams.GenesisHash
			} else {
				wantHash = tests[wantHeight-1].hash
			}

			gotBS := iter.BlockStamp()
			if gotBS.Height != wantHeight {
				tc.t.Errorf("NewIterateRecentBlocks block "+
					"stamp height mismatch -- got %d, "+
					"want %d", gotBS.Height, wantHeight)
				return false
			}
			if gotBS.Hash != *wantHash {
				tc.t.Errorf("NewIterateRecentBlocks block "+
					"stamp hash mismatch -- got %v, "+
					"want %v", gotBS.Hash, wantHash)
				return false
			}
			j++
		}

		// Ensure the maximum number of recent hashes works as expected.
		if i >= maxRecentHashes-1 && j != maxRecentHashes {
			tc.t.Errorf("NewIterateRecentBlocks iterated more than "+
				"the max number of expected blocks -- got %d, "+
				"want %d", j, maxRecentHashes)
			return false
		}
	}

	// Ensure rollback to block in recent history works as expected.
	blockStamp := wlocker.BlockStamp{
		Height: 10,
		Hash:   *tests[9].hash,
	}
	if err := tc.locker.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on rollback to block "+
			"in recent history: %v", err)
		return false
	}
	gotBlockStamp := tc.locker.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on rollback -- "+
			"got %v, want %v", gotBlockStamp, blockStamp)
		return false
	}

	// Ensure syncing to a block that is in the future as compared to the
	// current  block stamp clears the old recent blocks.
	blockStamp = wlocker.BlockStamp{
		Height: 100,
		Hash:   *newShaHash("000000007bc154e0fa7ea32218a72fe2c1bb9f86cf8c9ebf9a715ed27fdb229a"),
	}
	if err := tc.locker.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on future block stamp: "+
			"%v", err)
		return false
	}
	numRecentBlocks := 0
	iter := tc.locker.NewIterateRecentBlocks()
	for cont := iter != nil; cont; cont = iter.Prev() {
		numRecentBlocks++
	}
	if numRecentBlocks != 1 {
		tc.t.Errorf("Unexpected number of blocks after future block "+
			"stamp -- got %d, want %d", numRecentBlocks, 1)
		return false
	}

	// Rollback to a block that is not in the recent block history and
	// ensure it results in only that block.
	blockStamp = wlocker.BlockStamp{
		Height: 1,
		Hash:   *tests[0].hash,
	}
	if err := tc.locker.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on rollback to block "+
			"not in recent history: %v", err)
		return false
	}
	gotBlockStamp = tc.locker.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on rollback to "+
			"block not in recent history -- got %v, want %v",
			gotBlockStamp, blockStamp)
		return false
	}
	numRecentBlocks = 0
	iter = tc.locker.NewIterateRecentBlocks()
	for cont := iter != nil; cont; cont = iter.Prev() {
		numRecentBlocks++
	}
	if numRecentBlocks != 1 {
		tc.t.Errorf("Unexpected number of blocks after rollback to "+
			"block not in recent history -- got %d, want %d",
			numRecentBlocks, 1)
		return false
	}

	// Ensure syncing the locker to nil results in the synced to state
	// being the earliest block (genesis block in this case).
	if err := tc.locker.SetSyncedTo(nil); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on nil: %v", err)
		return false
	}
	blockStamp = wlocker.BlockStamp{
		Height: 0,
		Hash:   *chaincfg.MainNetParams.GenesisHash,
	}
	gotBlockStamp = tc.locker.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on nil -- "+
			"got %v, want %v", gotBlockStamp, blockStamp)
		return false
	}

	return true
}

// TestLocker performs a full suite of tests against the address locker API.
// It makes use of a test context because the address locker is persistent and
// much of the testing involves having specific state.
func TestLocker(t *testing.T) {
	t.Parallel()

	dbName := "mgrtest.bin"
	_ = os.Remove(dbName)
	db, mgrNamespace, err := createDbNamespace(dbName)
	if err != nil {
		t.Errorf("createDbNamespace: unexpected error: %v", err)
		return
	}
	defer os.Remove(dbName)
	defer db.Close()

	// Open locker that does not exist to ensure the expected error is
	// returned.
	_, err = wlocker.Open(mgrNamespace, pubPassphrase, nil)
	if !checkLockerError(t, "Open non-existant", err, wlocker.ErrNoExist) {
		return
	}

	// Create a new locker.
	mgr, err := wlocker.Create(mgrNamespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if err != nil {
		t.Errorf("Create: unexpected error: %v", err)
		return
	}

	// NOTE: Not using deferred close here since part of the tests is
	// explicitly closing the locker and then opening the existing one.

	// Attempt to create the locker again to ensure the expected error is
	// returned.
	_, err = wlocker.Create(mgrNamespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if !checkLockerError(t, "Create existing", err, wlocker.ErrAlreadyExists) {
		mgr.Close()
		return
	}

	// Run all of the locker API tests in create mode and close the
	// locker after they've completed
	testLockerAPI(&testContext{
		t:            t,
		db:           db,
		locker:      mgr,
		account:      0,
		create:       true,
	})
	mgr.Close()

	// Ensure the expected error is returned if the latest locker version
	// constant is bumped without writing code to actually do the upgrade.
	*wlocker.TstLatestMgrVersion++
	_, err = wlocker.Open(mgrNamespace, pubPassphrase, nil)
	if !checkLockerError(t, "Upgrade needed", err, wlocker.ErrUpgrade) {
		return
	}
	*wlocker.TstLatestMgrVersion--

	// Open the locker and run all the tests again in open mode which
	// avoids reinserting new addresses like the create mode tests do.
	mgr, err = wlocker.Open(mgrNamespace, pubPassphrase, nil)
	if err != nil {
		t.Errorf("Open: unexpected error: %v", err)
		return
	}
	defer mgr.Close()

	tc := &testContext{
		t:            t,
		db:           db,
		locker:      mgr,
		account:      0,
		create:       false,
	}
	testLockerAPI(tc)

	// Ensure that the locker sync state functionality works as expected.
	testSync(tc)

	// Unlock the locker so it can be closed with it unlocked to ensure
	// it works without issue.
	if err := mgr.Unlock(privPassphrase); err != nil {
		t.Errorf("Unlock: unexpected error: %v", err)
	}
}

// TestEncryptDecryptErrors ensures that errors which occur while encrypting and
// decrypting data return the expected errors.
func TestEncryptDecryptErrors(t *testing.T) {
	teardown, mgr := setupLocker(t)
	defer teardown()

	invalidKeyType := wlocker.CryptoKeyType(0xff)
	if _, err := mgr.Encrypt(invalidKeyType, []byte{}); err == nil {
		t.Fatalf("Encrypt accepted an invalid key type!")
	}

	if _, err := mgr.Decrypt(invalidKeyType, []byte{}); err == nil {
		t.Fatalf("Encrypt accepted an invalid key type!")
	}

	if !mgr.IsLocked() {
		t.Fatal("Locker should be locked at this point.")
	}

	var err error
	// Now the mgr is locked and encrypting/decrypting with private
	// keys should fail.
	_, err = mgr.Encrypt(wlocker.CKTPrivate, []byte{})
	checkLockerError(t, "encryption with private key fails when locker is locked",
		err, wlocker.ErrLocked)

	_, err = mgr.Decrypt(wlocker.CKTPrivate, []byte{})
	checkLockerError(t, "decryption with private key fails when locker is locked",
		err, wlocker.ErrLocked)

	// Unlock the locker for these tests
	if err = mgr.Unlock(privPassphrase); err != nil {
		t.Fatal("Attempted to unlock the locker, but failed:", err)
	}

	// Make sure to cover the ErrCrypto error path in Encrypt.
	wlocker.TstRunWithFailingCryptoKeyPriv(mgr, func() {
		_, err = mgr.Encrypt(wlocker.CKTPrivate, []byte{})
	})
	checkLockerError(t, "failed encryption", err, wlocker.ErrCrypto)

	// Make sure to cover the ErrCrypto error path in Decrypt.
	wlocker.TstRunWithFailingCryptoKeyPriv(mgr, func() {
		_, err = mgr.Decrypt(wlocker.CKTPrivate, []byte{})
	})
	checkLockerError(t, "failed decryption", err, wlocker.ErrCrypto)
}

// TestEncryptDecrypt ensures that encrypting and decrypting data with the
// the various crypto key types works as expected.
func TestEncryptDecrypt(t *testing.T) {
	teardown, mgr := setupLocker(t)
	defer teardown()

	plainText := []byte("this is a plaintext")

	// Make sure address locker is unlocked
	if err := mgr.Unlock(privPassphrase); err != nil {
		t.Fatal("Attempted to unlock the locker, but failed:", err)
	}

	keyTypes := []wlocker.CryptoKeyType{
		wlocker.CKTPublic,
		wlocker.CKTPrivate,
		wlocker.CKTScript,
	}

	for _, keyType := range keyTypes {
		cipherText, err := mgr.Encrypt(keyType, plainText)
		if err != nil {
			t.Fatalf("Failed to encrypt plaintext: %v", err)
		}

		decryptedCipherText, err := mgr.Decrypt(keyType, cipherText)
		if err != nil {
			t.Fatalf("Failed to decrypt plaintext: %v", err)
		}

		if !reflect.DeepEqual(decryptedCipherText, plainText) {
			t.Fatal("Got:", decryptedCipherText, ", want:", plainText)
		}
	}
}
