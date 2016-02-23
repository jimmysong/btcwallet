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

package wlocker

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (
	// LatestMgrVersion is the most recent locker version.
	LatestMgrVersion = 4
)

var (
	// latestMgrVersion is the most recent locker version as a variable so
	// the tests can change it to force errors.
	latestMgrVersion uint32 = LatestMgrVersion
)

// ObtainUserInputFunc is a function that reads a user input and returns it as
// a byte stream. It is used to accept data required during upgrades, for e.g.
// wallet seed and private passphrase.
type ObtainUserInputFunc func() ([]byte, error)

// maybeConvertDbError converts the passed error to a LockerError with an
// error code of ErrDatabase if it is not already a LockerError.  This is
// useful for potential errors returned from managed transaction an other parts
// of the walletdb database.
func maybeConvertDbError(err error) error {
	// When the error is already a LockerError, just return it.
	if _, ok := err.(LockerError); ok {
		return err
	}

	return lockerError(ErrDatabase, err.Error(), err)
}

// syncStatus represents a address synchronization status stored in the
// database.
type syncStatus uint8

// These constants define the various supported sync status types.
//
// NOTE: These are currently unused but are being defined for the possibility of
// supporting sync status on a per-address basis.
const (
	ssNone    syncStatus = 0 // not iota as they need to be stable for db
	ssPartial syncStatus = 1
	ssFull    syncStatus = 2
)
// Key names for various database fields.
var (
	// nullVall is null byte used as a flag value in a bucket entry
	nullVal = []byte{0}
	// meta is used to store meta-data about the address locker
	// e.g. last account number
	metaBucketName = []byte("meta")
	mainBucketName = []byte("main")
	syncBucketName = []byte("sync")

	// Db related key names (main bucket).
	mgrVersionName    = []byte("mgrver")
	mgrCreateDateName = []byte("mgrcreated")

	// Crypto related key names (main bucket).
	masterPrivKeyName   = []byte("mpriv")
	masterPubKeyName    = []byte("mpub")
	cryptoPrivKeyName   = []byte("cpriv")
	cryptoPubKeyName    = []byte("cpub")
	cryptoScriptKeyName = []byte("cscript")
	coinTypePrivKeyName = []byte("ctpriv")
	coinTypePubKeyName  = []byte("ctpub")
	watchingOnlyName    = []byte("watchonly")

	// Sync related key names (sync bucket).
	syncedToName     = []byte("syncedto")
	startBlockName   = []byte("startblock")
	recentBlocksName = []byte("recentblocks")
)

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// uint64ToBytes converts a 64 bit unsigned integer into a 8-byte slice in
// little-endian order: 1 -> [1 0 0 0 0 0 0 0].
func uint64ToBytes(number uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, number)
	return buf
}

// stringToBytes converts a string into a variable length byte slice in
// little-endian order: "abc" -> [3 0 0 0 61 62 63]
func stringToBytes(s string) []byte {
	// The serialized format is:
	//   <size><string>
	//
	// 4 bytes string size + string
	size := len(s)
	buf := make([]byte, 4+size)
	copy(buf[0:4], uint32ToBytes(uint32(size)))
	copy(buf[4:4+size], s)
	return buf
}

// fetchLockerVersion fetches the current locker version from the database.
func fetchLockerVersion(tx walletdb.Tx) (uint32, error) {
	mainBucket := tx.RootBucket().Bucket(mainBucketName)
	verBytes := mainBucket.Get(mgrVersionName)
	if verBytes == nil {
		str := "required version number not stored in database"
		return 0, lockerError(ErrDatabase, str, nil)
	}
	version := binary.LittleEndian.Uint32(verBytes)
	return version, nil
}

// putLockerVersion stores the provided version to the database.
func putLockerVersion(tx walletdb.Tx, version uint32) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	verBytes := uint32ToBytes(version)
	err := bucket.Put(mgrVersionName, verBytes)
	if err != nil {
		str := "failed to store version"
		return lockerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchMasterKeyParams loads the master key parameters needed to derive them
// (when given the correct user-supplied passphrase) from the database.  Either
// returned value can be nil, but in practice only the private key params will
// be nil for a watching-only database.
func fetchMasterKeyParams(tx walletdb.Tx) ([]byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Load the master public key parameters.  Required.
	val := bucket.Get(masterPubKeyName)
	if val == nil {
		str := "required master public key parameters not stored in " +
			"database"
		return nil, nil, lockerError(ErrDatabase, str, nil)
	}
	pubParams := make([]byte, len(val))
	copy(pubParams, val)

	// Load the master private key parameters if they were stored.
	var privParams []byte
	val = bucket.Get(masterPrivKeyName)
	if val != nil {
		privParams = make([]byte, len(val))
		copy(privParams, val)
	}

	return pubParams, privParams, nil
}

// putMasterKeyParams stores the master key parameters needed to derive them
// to the database.  Either parameter can be nil in which case no value is
// written for the parameter.
func putMasterKeyParams(tx walletdb.Tx, pubParams, privParams []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if privParams != nil {
		err := bucket.Put(masterPrivKeyName, privParams)
		if err != nil {
			str := "failed to store master private key parameters"
			return lockerError(ErrDatabase, str, err)
		}
	}

	if pubParams != nil {
		err := bucket.Put(masterPubKeyName, pubParams)
		if err != nil {
			str := "failed to store master public key parameters"
			return lockerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchCoinTypeKeys loads the encrypted cointype keys which are in turn used to
// derive the extended keys for all accounts.
func fetchCoinTypeKeys(tx walletdb.Tx) ([]byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	coinTypePubKeyEnc := bucket.Get(coinTypePubKeyName)
	if coinTypePubKeyEnc == nil {
		str := "required encrypted cointype public key not stored in database"
		return nil, nil, lockerError(ErrDatabase, str, nil)
	}

	coinTypePrivKeyEnc := bucket.Get(coinTypePrivKeyName)
	if coinTypePrivKeyEnc == nil {
		str := "required encrypted cointype private key not stored in database"
		return nil, nil, lockerError(ErrDatabase, str, nil)
	}
	return coinTypePubKeyEnc, coinTypePrivKeyEnc, nil
}

// putCoinTypeKeys stores the encrypted cointype keys which are in turn used to
// derive the extended keys for all accounts.  Either parameter can be nil in which
// case no value is written for the parameter.
func putCoinTypeKeys(tx walletdb.Tx, coinTypePubKeyEnc []byte, coinTypePrivKeyEnc []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if coinTypePubKeyEnc != nil {
		err := bucket.Put(coinTypePubKeyName, coinTypePubKeyEnc)
		if err != nil {
			str := "failed to store encrypted cointype public key"
			return lockerError(ErrDatabase, str, err)
		}
	}

	if coinTypePrivKeyEnc != nil {
		err := bucket.Put(coinTypePrivKeyName, coinTypePrivKeyEnc)
		if err != nil {
			str := "failed to store encrypted cointype private key"
			return lockerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchCryptoKeys loads the encrypted crypto keys which are in turn used to
// protect the extended keys, imported keys, and scripts.  Any of the returned
// values can be nil, but in practice only the crypto private and script keys
// will be nil for a watching-only database.
func fetchCryptoKeys(tx walletdb.Tx) ([]byte, []byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Load the crypto public key parameters.  Required.
	val := bucket.Get(cryptoPubKeyName)
	if val == nil {
		str := "required encrypted crypto public not stored in database"
		return nil, nil, nil, lockerError(ErrDatabase, str, nil)
	}
	pubKey := make([]byte, len(val))
	copy(pubKey, val)

	// Load the crypto private key parameters if they were stored.
	var privKey []byte
	val = bucket.Get(cryptoPrivKeyName)
	if val != nil {
		privKey = make([]byte, len(val))
		copy(privKey, val)
	}

	// Load the crypto script key parameters if they were stored.
	var scriptKey []byte
	val = bucket.Get(cryptoScriptKeyName)
	if val != nil {
		scriptKey = make([]byte, len(val))
		copy(scriptKey, val)
	}

	return pubKey, privKey, scriptKey, nil
}

// putCryptoKeys stores the encrypted crypto keys which are in turn used to
// protect the extended and imported keys.  Either parameter can be nil in which
// case no value is written for the parameter.
func putCryptoKeys(tx walletdb.Tx, pubKeyEncrypted, privKeyEncrypted, scriptKeyEncrypted []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if pubKeyEncrypted != nil {
		err := bucket.Put(cryptoPubKeyName, pubKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto public key"
			return lockerError(ErrDatabase, str, err)
		}
	}

	if privKeyEncrypted != nil {
		err := bucket.Put(cryptoPrivKeyName, privKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto private key"
			return lockerError(ErrDatabase, str, err)
		}
	}

	if scriptKeyEncrypted != nil {
		err := bucket.Put(cryptoScriptKeyName, scriptKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto script key"
			return lockerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// deletePrivateKeys removes all private key material from the database.
//
// NOTE: Care should be taken when calling this function.  It is primarily
// intended for use in converting to a watching-only copy.  Removing the private
// keys from the main database without also marking it watching-only will result
// in an unusable database.  It will also make any imported scripts and private
// keys unrecoverable unless there is a backup copy available.
func deletePrivateKeys(tx walletdb.Tx) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Delete the master private key params and the crypto private and
	// script keys.
	if err := bucket.Delete(masterPrivKeyName); err != nil {
		str := "failed to delete master private key parameters"
		return lockerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoPrivKeyName); err != nil {
		str := "failed to delete crypto private key"
		return lockerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoScriptKeyName); err != nil {
		str := "failed to delete crypto script key"
		return lockerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(coinTypePrivKeyName); err != nil {
		str := "failed to delete cointype private key"
		return lockerError(ErrDatabase, str, err)
	}

	return nil
}

// fetchSyncedTo loads the block stamp the locker is synced to from the
// database.
func fetchSyncedTo(tx walletdb.Tx) (*BlockStamp, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized synced to format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(syncedToName)
	if len(buf) != 36 {
		str := "malformed sync information stored in database"
		return nil, lockerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])
	return &bs, nil
}

// putSyncedTo stores the provided synced to blockstamp to the database.
func putSyncedTo(tx walletdb.Tx, bs *BlockStamp) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized synced to format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bs.Height))
	copy(buf[4:36], bs.Hash[0:32])

	err := bucket.Put(syncedToName, buf)
	if err != nil {
		str := fmt.Sprintf("failed to store sync information %v", bs.Hash)
		return lockerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchStartBlock loads the start block stamp for the locker from the
// database.
func fetchStartBlock(tx walletdb.Tx) (*BlockStamp, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(startBlockName)
	if len(buf) != 36 {
		str := "malformed start block stored in database"
		return nil, lockerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])
	return &bs, nil
}

// putStartBlock stores the provided start block stamp to the database.
func putStartBlock(tx walletdb.Tx, bs *BlockStamp) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bs.Height))
	copy(buf[4:36], bs.Hash[0:32])

	err := bucket.Put(startBlockName, buf)
	if err != nil {
		str := fmt.Sprintf("failed to store start block %v", bs.Hash)
		return lockerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchRecentBlocks returns the height of the most recent block height and
// hashes of the most recent blocks.
func fetchRecentBlocks(tx walletdb.Tx) (int32, []wire.ShaHash, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized recent blocks format is:
	//   <blockheight><numhashes><blockhashes>
	//
	// 4 bytes recent block height + 4 bytes number of hashes + raw hashes
	// at 32 bytes each.

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	buf := bucket.Get(recentBlocksName)
	if len(buf) < 8 {
		str := "malformed recent blocks stored in database"
		return 0, nil, lockerError(ErrDatabase, str, nil)
	}

	recentHeight := int32(binary.LittleEndian.Uint32(buf[0:4]))
	numHashes := binary.LittleEndian.Uint32(buf[4:8])
	recentHashes := make([]wire.ShaHash, numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(recentHashes[i][:], buf[offset:offset+32])
		offset += 32
	}

	return recentHeight, recentHashes, nil
}

// putRecentBlocks stores the provided start block stamp to the database.
func putRecentBlocks(tx walletdb.Tx, recentHeight int32, recentHashes []wire.ShaHash) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized recent blocks format is:
	//   <blockheight><numhashes><blockhashes>
	//
	// 4 bytes recent block height + 4 bytes number of hashes + raw hashes
	// at 32 bytes each.
	numHashes := uint32(len(recentHashes))
	buf := make([]byte, 8+(numHashes*32))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recentHeight))
	binary.LittleEndian.PutUint32(buf[4:8], numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(buf[offset:offset+32], recentHashes[i][:])
		offset += 32
	}

	err := bucket.Put(recentBlocksName, buf)
	if err != nil {
		str := "failed to store recent blocks"
		return lockerError(ErrDatabase, str, err)
	}
	return nil
}

// lockerExists returns whether or not the locker has already been created
// in the given database namespace.
func lockerExists(namespace walletdb.Namespace) (bool, error) {
	var exists bool
	err := namespace.View(func(tx walletdb.Tx) error {
		mainBucket := tx.RootBucket().Bucket(mainBucketName)
		exists = mainBucket != nil
		return nil
	})
	if err != nil {
		str := fmt.Sprintf("failed to obtain database view: %v", err)
		return false, lockerError(ErrDatabase, str, err)
	}
	return exists, nil
}

// createLockerNS creates the initial namespace structure needed for all of the
// locker data.  This includes things such as all of the buckets as well as the
// version and creation date.
func createLockerNS(namespace walletdb.Namespace) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		rootBucket := tx.RootBucket()
		mainBucket, err := rootBucket.CreateBucket(mainBucketName)
		if err != nil {
			str := "failed to create main bucket"
			return lockerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(syncBucketName)
		if err != nil {
			str := "failed to create sync bucket"
			return lockerError(ErrDatabase, str, err)
		}


		_, err = rootBucket.CreateBucket(metaBucketName)
		if err != nil {
			str := "failed to create a meta bucket"
			return lockerError(ErrDatabase, str, err)
		}

		if err := putLockerVersion(tx, latestMgrVersion); err != nil {
			return err
		}

		createDate := uint64(time.Now().Unix())
		var dateBytes [8]byte
		binary.LittleEndian.PutUint64(dateBytes[:], createDate)
		err = mainBucket.Put(mgrCreateDateName, dateBytes[:])
		if err != nil {
			str := "failed to store database creation time"
			return lockerError(ErrDatabase, str, err)
		}

		return nil
	})
	if err != nil {
		str := "failed to update database"
		return lockerError(ErrDatabase, str, err)
	}

	return nil
}

// upgradeToVersion2 upgrades the database from version 1 to version 2
// 'usedAddrBucketName' a bucket for storing addrs flagged as marked is
// initialized and it will be updated on the next rescan.
func upgradeToVersion2(namespace walletdb.Namespace) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		currentMgrVersion := uint32(2)
		if err := putLockerVersion(tx, currentMgrVersion); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// upgradeLocker upgrades the data in the provided locker namespace to newer
// versions as neeeded.
func upgradeLocker(namespace walletdb.Namespace, pubPassPhrase []byte, cbs *OpenCallbacks) error {
	var version uint32
	err := namespace.View(func(tx walletdb.Tx) error {
		var err error
		version, err = fetchLockerVersion(tx)
		return err
	})
	if err != nil {
		str := "failed to fetch version for update"
		return lockerError(ErrDatabase, str, err)
	}

	// NOTE: There are currently no upgrades, but this is provided here as a
	// template for how to properly do upgrades.  Each function to upgrade
	// to the next version must include serializing the new version as a
	// part of the same transaction so any failures in upgrades to later
	// versions won't leave the database in an inconsistent state.  The
	// putLockerVersion function provides a convenient mechanism for that
	// purpose.
	//
	// Upgrade one version at a time so it is possible to upgrade across
	// an aribtary number of versions without needing to write a bunch of
	// additional code to go directly from version X to Y.
	// if version < 2 {
	// 	// Upgrade from version 1 to 2.
	//	if err := upgradeToVersion2(namespace); err != nil {
	//		return err
	//	}
	//
	//	// The locker is now at version 2.
	//	version = 2
	// }
	// if version < 3 {
	// 	// Upgrade from version 2 to 3.
	//	if err := upgradeToVersion3(namespace); err != nil {
	//		return err
	//	}
	//
	//	// The locker is now at version 3.
	//	version = 3
	// }

	if version < 2 {
		// Upgrade from version 1 to 2.
		if err := upgradeToVersion2(namespace); err != nil {
			return err
		}

		// The locker is now at version 2.
		version = 2
	}

	if version < 3 {
		if cbs == nil || cbs.ObtainSeed == nil || cbs.ObtainPrivatePass == nil {
			str := "failed to obtain seed and private passphrase required for upgrade"
			return lockerError(ErrDatabase, str, err)
		}

		seed, err := cbs.ObtainSeed()
		if err != nil {
			return err
		}
		privPassPhrase, err := cbs.ObtainPrivatePass()
		if err != nil {
			return err
		}
		// Upgrade from version 2 to 3.
		if err := upgradeToVersion3(namespace, seed, privPassPhrase, pubPassPhrase); err != nil {
			return err
		}

		// The locker is now at version 3.
		version = 3
	}

	if version < 4 {
		if err := upgradeToVersion4(namespace, pubPassPhrase); err != nil {
			return err
		}

		// The locker is now at version 4.
		version = 4
	}

	// Ensure the locker is upraded to the latest version.  This check is
	// to intentionally cause a failure if the locker version is updated
	// without writing code to handle the upgrade.
	if version < latestMgrVersion {
		str := fmt.Sprintf("the latest locker version is %d, but the "+
			"current version after upgrades is only %d",
			latestMgrVersion, version)
		return lockerError(ErrUpgrade, str, nil)
	}

	return nil
}

// upgradeToVersion3 upgrades the database from version 2 to version 3
// The following buckets were introduced in version 3 to support account names:
// * acctNameIdxBucketName
// * acctIDIdxBucketName
// * metaBucketName
func upgradeToVersion3(namespace walletdb.Namespace, seed, privPassPhrase, pubPassPhrase []byte) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		currentMgrVersion := uint32(3)
		rootBucket := tx.RootBucket()

		woMgr, err := loadLocker(namespace, pubPassPhrase)
		if err != nil {
			return err
		}
		defer woMgr.Close()

		err = woMgr.Unlock(privPassPhrase)
		if err != nil {
			return err
		}

		_, err = rootBucket.CreateBucket(metaBucketName)
		if err != nil {
			str := "failed to create a meta bucket"
			return lockerError(ErrDatabase, str, err)
		}

		// Write current locker version
		if err := putLockerVersion(tx, currentMgrVersion); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// upgradeToVersion4 upgrades the database from version 3 to version 4.  The
// default account remains unchanged (even if it was modified by the user), but
// the empty string alias to the default account is removed.
func upgradeToVersion4(namespace walletdb.Namespace, pubPassPhrase []byte) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		// Write new locker version.
		err := putLockerVersion(tx, 4)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}
