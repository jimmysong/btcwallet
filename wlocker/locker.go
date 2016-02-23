/*
 * Copyright (c) 2014-2016 The btcsuite developers
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
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/internal/zero"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/walletdb"
)

const (

	// saltSize is the number of bytes of the salt used when hashing
	// private passphrases.
	saltSize = 32
)

// ScryptOptions is used to hold the scrypt parameters needed when deriving new
// passphrase keys.
type ScryptOptions struct {
	N, R, P int
}

// OpenCallbacks houses caller-provided callbacks that may be called when
// opening an existing manager.  The open blocks on the execution of these
// functions.
type OpenCallbacks struct {
	// ObtainSeed is a callback function that is potentially invoked during
	// upgrades.  It is intended to be used to request the wallet seed
	// from the user (or any other mechanism the caller deems fit).
	ObtainSeed ObtainUserInputFunc
	// ObtainPrivatePass is a callback function that is potentially invoked
	// during upgrades.  It is intended to be used to request the wallet
	// private passphrase from the user (or any other mechanism the caller
	// deems fit).
	ObtainPrivatePass ObtainUserInputFunc
}

// DefaultConfig is an instance of the Options struct initialized with default
// configuration options.
var DefaultScryptOptions = ScryptOptions{
	N: 262144, // 2^18
	R: 8,
	P: 1,
}

// defaultNewSecretKey returns a new secret key.  See newSecretKey.
func defaultNewSecretKey(passphrase *[]byte, config *ScryptOptions) (*snacl.SecretKey, error) {
	return snacl.NewSecretKey(passphrase, config.N, config.R, config.P)
}

// newSecretKey is used as a way to replace the new secret key generation
// function used so tests can provide a version that fails for testing error
// paths.
var newSecretKey = defaultNewSecretKey

// EncryptorDecryptor provides an abstraction on top of snacl.CryptoKey so that
// our tests can use dependency injection to force the behaviour they need.
type EncryptorDecryptor interface {
	Encrypt(in []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
	Bytes() []byte
	CopyBytes([]byte)
	Zero()
}

// cryptoKey extends snacl.CryptoKey to implement EncryptorDecryptor.
type cryptoKey struct {
	snacl.CryptoKey
}

// Bytes returns a copy of this crypto key's byte slice.
func (ck *cryptoKey) Bytes() []byte {
	return ck.CryptoKey[:]
}

// CopyBytes copies the bytes from the given slice into this CryptoKey.
func (ck *cryptoKey) CopyBytes(from []byte) {
	copy(ck.CryptoKey[:], from)
}

// defaultNewCryptoKey returns a new CryptoKey.  See newCryptoKey.
func defaultNewCryptoKey() (EncryptorDecryptor, error) {
	key, err := snacl.GenerateCryptoKey()
	if err != nil {
		return nil, err
	}
	return &cryptoKey{*key}, nil
}

// CryptoKeyType is used to differentiate between different kinds of
// crypto keys.
type CryptoKeyType byte

// Crypto key types.
const (
	// CKTPrivate specifies the key that is used for encryption of private
	// key material such as derived extended private keys and imported
	// private keys.
	CKTPrivate CryptoKeyType = iota

	// CKTScript specifies the key that is used for encryption of scripts.
	CKTScript

	// CKTPublic specifies the key that is used for encryption of public
	// key material such as dervied extended public keys and imported public
	// keys.
	CKTPublic
)

// newCryptoKey is used as a way to replace the new crypto key generation
// function used so tests can provide a version that fails for testing error
// paths.
var newCryptoKey = defaultNewCryptoKey

// Locker represents a concurrency safe crypto currency address locker and
// key store.
type Locker struct {
	mtx sync.RWMutex

	namespace    walletdb.Namespace
	syncState    syncState
	locked       bool
	closed       bool

	// masterKeyPub is the secret key used to secure the cryptoKeyPub key
	// and masterKeyPriv is the secret key used to secure the cryptoKeyPriv
	// key.  This approach is used because it makes changing the passwords
	// much simpler as it then becomes just changing these keys.  It also
	// provides future flexibility.
	//
	// NOTE: This is not the same thing as BIP0032 master node extended
	// key.
	//
	// The underlying master private key will be zeroed when the address
	// locker is locked.
	masterKeyPub  *snacl.SecretKey
	masterKeyPriv *snacl.SecretKey

	// cryptoKeyPub is the key used to encrypt public extended keys and
	// addresses.
	cryptoKeyPub EncryptorDecryptor

	// cryptoKeyPriv is the key used to encrypt private data such as the
	// master hierarchical deterministic extended key.
	//
	// This key will be zeroed when the address locker is locked.
	cryptoKeyPrivEncrypted []byte
	cryptoKeyPriv          EncryptorDecryptor

	// cryptoKeyScript is the key used to encrypt script data.
	//
	// This key will be zeroed when the address locker is locked.
	cryptoKeyScriptEncrypted []byte
	cryptoKeyScript          EncryptorDecryptor

	// privPassphraseSalt and hashedPrivPassphrase allow for the secure
	// detection of a correct passphrase on locker unlock when the
	// locker is already unlocked.  The hash is zeroed each lock.
	privPassphraseSalt   [saltSize]byte
	hashedPrivPassphrase [sha512.Size]byte
}

// lock performs a best try effort to remove and zero all secret keys associated
// with the address locker.
//
// This function MUST be called with the locker lock held for writes.
func (m *Locker) lock() {
	// Remove clear text private master and crypto keys from memory.
	m.cryptoKeyScript.Zero()
	m.cryptoKeyPriv.Zero()
	m.masterKeyPriv.Zero()

	// Zero the hashed passphrase.
	zero.Bytea64(&m.hashedPrivPassphrase)

	// NOTE: m.cryptoKeyPub is intentionally not cleared here as the address
	// locker needs to be able to continue to read and decrypt public data
	// which uses a separate derived key from the database even when it is
	// locked.

	m.locked = true
}

// zeroSensitivePublicData performs a best try effort to remove and zero all
// sensitive public data associated with the address locker such as
// hierarchical deterministic extended public keys and the crypto public keys.
func (m *Locker) zeroSensitivePublicData() {
	// Remove clear text public master and crypto keys from memory.
	m.cryptoKeyPub.Zero()
	m.masterKeyPub.Zero()
}

// Close cleanly shuts down the locker.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address locker from memory.
func (m *Locker) Close() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Attempt to clear private key material from memory.
	if !m.locked {
		m.lock()
	}

	// Attempt to clear sensitive public key material from memory too.
	m.zeroSensitivePublicData()

	m.closed = true
	return nil
}

// ChangePassphrase changes either the public or private passphrase to the
// provided value depending on the private flag.  In order to change the private
// password, the address locker must not be watching-only.  The new passphrase
// keys are derived using the scrypt parameters in the options, so changing the
// passphrase may be used to bump the computational difficulty needed to brute
// force the passphrase.
func (m *Locker) ChangePassphrase(oldPassphrase, newPassphrase []byte, private bool, config *ScryptOptions) error {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Ensure the provided old passphrase is correct.  This check is done
	// using a copy of the appropriate master key depending on the private
	// flag to ensure the current state is not altered.  The temp key is
	// cleared when done to avoid leaving a copy in memory.
	var keyName string
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	if private {
		keyName = "private"
		secretKey.Parameters = m.masterKeyPriv.Parameters
	} else {
		keyName = "public"
		secretKey.Parameters = m.masterKeyPub.Parameters
	}
	if private {
		secretKey.Parameters = m.masterKeyPriv.Parameters
	} else {
		secretKey.Parameters = m.masterKeyPub.Parameters
	}
	if err := secretKey.DeriveKey(&oldPassphrase); err != nil {
		if err == snacl.ErrInvalidPassword {
			str := fmt.Sprintf("invalid passphrase for %s master "+
				"key", keyName)
			return lockerError(ErrWrongPassphrase, str, nil)
		}

		str := fmt.Sprintf("failed to derive %s master key", keyName)
		return lockerError(ErrCrypto, str, err)
	}
	defer secretKey.Zero()

	// Generate a new master key from the passphrase which is used to secure
	// the actual secret keys.
	newMasterKey, err := newSecretKey(&newPassphrase, config)
	if err != nil {
		str := "failed to create new master private key"
		return lockerError(ErrCrypto, str, err)
	}
	newKeyParams := newMasterKey.Marshal()

	if private {
		// Technically, the locked state could be checked here to only
		// do the decrypts when the address locker is locked as the
		// clear text keys are already available in memory when it is
		// unlocked, but this is not a hot path, decryption is quite
		// fast, and it's less cyclomatic complexity to simply decrypt
		// in either case.

		// Create a new salt that will be used for hashing the new
		// passphrase each unlock.
		var passphraseSalt [saltSize]byte
		_, err := rand.Read(passphraseSalt[:])
		if err != nil {
			str := "failed to read random source for passhprase salt"
			return lockerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto private key using the new master
		// private key.
		decPriv, err := secretKey.Decrypt(m.cryptoKeyPrivEncrypted)
		if err != nil {
			str := "failed to decrypt crypto private key"
			return lockerError(ErrCrypto, str, err)
		}
		encPriv, err := newMasterKey.Encrypt(decPriv)
		zero.Bytes(decPriv)
		if err != nil {
			str := "failed to encrypt crypto private key"
			return lockerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto script key using the new master private
		// key.
		decScript, err := secretKey.Decrypt(m.cryptoKeyScriptEncrypted)
		if err != nil {
			str := "failed to decrypt crypto script key"
			return lockerError(ErrCrypto, str, err)
		}
		encScript, err := newMasterKey.Encrypt(decScript)
		zero.Bytes(decScript)
		if err != nil {
			str := "failed to encrypt crypto script key"
			return lockerError(ErrCrypto, str, err)
		}

		// When the locker is locked, ensure the new clear text master
		// key is cleared from memory now that it is no longer needed.
		// If unlocked, create the new passphrase hash with the new
		// passphrase and salt.
		var hashedPassphrase [sha512.Size]byte
		if m.locked {
			newMasterKey.Zero()
		} else {
			saltedPassphrase := append(passphraseSalt[:],
				newPassphrase...)
			hashedPassphrase = sha512.Sum512(saltedPassphrase)
			zero.Bytes(saltedPassphrase)
		}

		// Save the new keys and params to the the db in a single
		// transaction.
		err = m.namespace.Update(func(tx walletdb.Tx) error {
			err := putCryptoKeys(tx, nil, encPriv, encScript)
			if err != nil {
				return err
			}

			return putMasterKeyParams(tx, nil, newKeyParams)
		})
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		copy(m.cryptoKeyPrivEncrypted[:], encPriv)
		copy(m.cryptoKeyScriptEncrypted[:], encScript)
		m.masterKeyPriv.Zero() // Clear the old key.
		m.masterKeyPriv = newMasterKey
		m.privPassphraseSalt = passphraseSalt
		m.hashedPrivPassphrase = hashedPassphrase
	} else {
		// Re-encrypt the crypto public key using the new master public
		// key.
		encryptedPub, err := newMasterKey.Encrypt(m.cryptoKeyPub.Bytes())
		if err != nil {
			str := "failed to encrypt crypto public key"
			return lockerError(ErrCrypto, str, err)
		}

		// Save the new keys and params to the the db in a single
		// transaction.
		err = m.namespace.Update(func(tx walletdb.Tx) error {
			err := putCryptoKeys(tx, encryptedPub, nil, nil)
			if err != nil {
				return err
			}

			return putMasterKeyParams(tx, newKeyParams, nil)
		})
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		m.masterKeyPub.Zero()
		m.masterKeyPub = newMasterKey
	}

	return nil
}


// IsLocked returns whether or not the address managed is locked.  When it is
// unlocked, the decryption key needed to decrypt private keys used for signing
// is in memory.
func (m *Locker) IsLocked() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.locked
}

// Lock performs a best try effort to remove and zero all secret keys associated
// with the address locker.
//
// This function will return an error if invoked on a watching-only address
// locker.
func (m *Locker) Lock() error {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Error on attempt to lock an already locked locker.
	if m.locked {
		return lockerError(ErrLocked, errLocked, nil)
	}

	m.lock()
	return nil
}


// Unlock derives the master private key from the specified passphrase.  An
// invalid passphrase will return an error.  Otherwise, the derived secret key
// is stored in memory until the address locker is locked.  Any failures that
// occur during this function will result in the address locker being locked,
// even if it was already unlocked prior to calling this function.
//
// This function will return an error if invoked on a watching-only address
// locker.
func (m *Locker) Unlock(passphrase []byte) error {

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Avoid actually unlocking if the locker is already unlocked
	// and the passphrases match.
	if !m.locked {
		saltedPassphrase := append(m.privPassphraseSalt[:],
			passphrase...)
		hashedPassphrase := sha512.Sum512(saltedPassphrase)
		zero.Bytes(saltedPassphrase)
		if hashedPassphrase != m.hashedPrivPassphrase {
			m.lock()
			str := "invalid passphrase for master private key"
			return lockerError(ErrWrongPassphrase, str, nil)
		}
		return nil
	}

	// Derive the master private key using the provided passphrase.
	if err := m.masterKeyPriv.DeriveKey(&passphrase); err != nil {
		m.lock()
		if err == snacl.ErrInvalidPassword {
			str := "invalid passphrase for master private key"
			return lockerError(ErrWrongPassphrase, str, nil)
		}

		str := "failed to derive master private key"
		return lockerError(ErrCrypto, str, err)
	}

	// Use the master private key to decrypt the crypto private key.
	decryptedKey, err := m.masterKeyPriv.Decrypt(m.cryptoKeyPrivEncrypted)
	if err != nil {
		m.lock()
		str := "failed to decrypt crypto private key"
		return lockerError(ErrCrypto, str, err)
	}
	m.cryptoKeyPriv.CopyBytes(decryptedKey)
	zero.Bytes(decryptedKey)


	m.locked = false
	saltedPassphrase := append(m.privPassphraseSalt[:], passphrase...)
	m.hashedPrivPassphrase = sha512.Sum512(saltedPassphrase)
	zero.Bytes(saltedPassphrase)
	return nil
}

// selectCryptoKey selects the appropriate crypto key based on the key type. An
// error is returned when an invalid key type is specified or the requested key
// requires the locker to be unlocked when it isn't.
//
// This function MUST be called with the locker lock held for reads.
func (m *Locker) selectCryptoKey(keyType CryptoKeyType) (EncryptorDecryptor, error) {
	if keyType == CKTPrivate || keyType == CKTScript {
		// The locker must be unlocked to work with the private keys.
		if m.locked {
			return nil, lockerError(ErrLocked, errLocked, nil)
		}
	}

	var cryptoKey EncryptorDecryptor
	switch keyType {
	case CKTPrivate:
		cryptoKey = m.cryptoKeyPriv
	case CKTScript:
		cryptoKey = m.cryptoKeyScript
	case CKTPublic:
		cryptoKey = m.cryptoKeyPub
	default:
 		return nil, lockerError(ErrInvalidKeyType, "invalid key type",
			nil)
	}

	return cryptoKey, nil
}

// Encrypt in using the crypto key type specified by keyType.
func (m *Locker) Encrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Encryption must be performed under the locker mutex since the
	// keys are cleared when the locker is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	encrypted, err := cryptoKey.Encrypt(in)
	if err != nil {
		return nil, lockerError(ErrCrypto, "failed to encrypt", err)
	}
	return encrypted, nil
}

// Decrypt in using the crypto key type specified by keyType.
func (m *Locker) Decrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Decryption must be performed under the locker mutex since the
	// keys are cleared when the locker is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	decrypted, err := cryptoKey.Decrypt(in)
	if err != nil {
		return nil, lockerError(ErrCrypto, "failed to decrypt", err)
	}
	return decrypted, nil
}

// newLocker returns a new locked address locker with the given parameters.
func newLocker(namespace walletdb.Namespace,
	masterKeyPub *snacl.SecretKey, masterKeyPriv *snacl.SecretKey,
	cryptoKeyPub EncryptorDecryptor, cryptoKeyPrivEncrypted,
	cryptoKeyScriptEncrypted []byte, syncInfo *syncState,
	privPassphraseSalt [saltSize]byte) *Locker {

	return &Locker{
		namespace:                namespace,
		syncState:                *syncInfo,
		locked:                   true,
		masterKeyPub:             masterKeyPub,
		masterKeyPriv:            masterKeyPriv,
		cryptoKeyPub:             cryptoKeyPub,
		cryptoKeyPrivEncrypted:   cryptoKeyPrivEncrypted,
		cryptoKeyPriv:            &cryptoKey{},
		cryptoKeyScriptEncrypted: cryptoKeyScriptEncrypted,
		cryptoKeyScript:          &cryptoKey{},
		privPassphraseSalt:       privPassphraseSalt,
	}
}


// loadLocker returns a new address locker that results from loading it from
// the passed opened database.  The public passphrase is required to decrypt the
// public keys.
func loadLocker(namespace walletdb.Namespace, pubPassphrase []byte) (*Locker, error) {
	// Perform all database lookups in a read-only view.
	var masterKeyPubParams, masterKeyPrivParams []byte
	var cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc []byte
	var syncedTo, startBlock *BlockStamp
	var recentHeight int32
	var recentHashes []wire.ShaHash
	err := namespace.View(func(tx walletdb.Tx) error {
		// Load whether or not the locker is watching-only from the db.
		var err error

		// Load the master key params from the db.
		masterKeyPubParams, masterKeyPrivParams, err =
			fetchMasterKeyParams(tx)
		if err != nil {
			return err
		}

		// Load the crypto keys from the db.
		cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, err =
			fetchCryptoKeys(tx)
		if err != nil {
			return err
		}

		// Load the sync state from the db.
		syncedTo, err = fetchSyncedTo(tx)
		if err != nil {
			return err
		}
		startBlock, err = fetchStartBlock(tx)
		if err != nil {
			return err
		}

		recentHeight, recentHashes, err = fetchRecentBlocks(tx)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// When not a watching-only locker, set the master private key params,
	// but don't derive it now since the locker starts off locked.
	var masterKeyPriv snacl.SecretKey
	err = masterKeyPriv.Unmarshal(masterKeyPrivParams)
	if err != nil {
		str := "failed to unmarshal master private key"
		return nil, lockerError(ErrCrypto, str, err)
	}

	// Derive the master public key using the serialized params and provided
	// passphrase.
	var masterKeyPub snacl.SecretKey
	if err := masterKeyPub.Unmarshal(masterKeyPubParams); err != nil {
		str := "failed to unmarshal master public key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	if err := masterKeyPub.DeriveKey(&pubPassphrase); err != nil {
		str := "invalid passphrase for master public key"
		return nil, lockerError(ErrWrongPassphrase, str, nil)
	}

	// Use the master public key to decrypt the crypto public key.
	cryptoKeyPub := &cryptoKey{snacl.CryptoKey{}}
	cryptoKeyPubCT, err := masterKeyPub.Decrypt(cryptoKeyPubEnc)
	if err != nil {
		str := "failed to decrypt crypto public key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	cryptoKeyPub.CopyBytes(cryptoKeyPubCT)
	zero.Bytes(cryptoKeyPubCT)

	// Create the sync state struct.
	syncInfo := newSyncState(startBlock, syncedTo, recentHeight, recentHashes)

	// Generate private passphrase salt.
	var privPassphraseSalt [saltSize]byte
	_, err = rand.Read(privPassphraseSalt[:])
	if err != nil {
		str := "failed to read random source for passphrase salt"
		return nil, lockerError(ErrCrypto, str, err)
	}

	// Create new address locker with the given parameters.  Also, override
	// the defaults for the additional fields which are not specified in the
	// call to new with the values loaded from the database.
	mgr := newLocker(namespace, &masterKeyPub, &masterKeyPriv,
		cryptoKeyPub, cryptoKeyPrivEnc, cryptoKeyScriptEnc, syncInfo,
		privPassphraseSalt)
	return mgr, nil
}

// Open loads an existing address locker from the given namespace.  The public
// passphrase is required to decrypt the public keys used to protect the public
// information such as addresses.  This is important since access to BIP0032
// extended keys means it is possible to generate all future addresses.
//
// If a config structure is passed to the function, that configuration
// will override the defaults.
//
// A LockerError with an error code of ErrNoExist will be returned if the
// passed locker does not exist in the specified namespace.
func Open(namespace walletdb.Namespace, pubPassphrase []byte, cbs *OpenCallbacks) (*Locker, error) {
	// Return an error if the locker has NOT already been created in the
	// given database namespace.
	exists, err := lockerExists(namespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		str := "the specified address locker does not exist"
		return nil, lockerError(ErrNoExist, str, nil)
	}

	// Upgrade the locker to the latest version as needed.
	if err := upgradeLocker(namespace, pubPassphrase, cbs); err != nil {
		return nil, err
	}

	return loadLocker(namespace, pubPassphrase)
}

// Create returns a new locked address locker in the given namespace.  The
// seed must conform to the standards described in hdkeychain.NewMaster and will
// be used to create the master root node from which all hierarchical
// deterministic addresses are derived.  This allows all chained addresses in
// the address locker to be recovered by using the same seed.
//
// All private and public keys and information are protected by secret keys
// derived from the provided private and public passphrases.  The public
// passphrase is required on subsequent opens of the address locker, and the
// private passphrase is required to unlock the address locker in order to gain
// access to any private keys and information.
//
// If a config structure is passed to the function, that configuration
// will override the defaults.
//
// A LockerError with an error code of ErrAlreadyExists will be returned the
// address locker already exists in the specified namespace.
func Create(namespace walletdb.Namespace, seed, pubPassphrase, privPassphrase []byte, chainParams *chaincfg.Params, config *ScryptOptions) (*Locker, error) {
	// Return an error if the locker has already been created in the given
	// database namespace.
	exists, err := lockerExists(namespace)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, lockerError(ErrAlreadyExists, errAlreadyExists, nil)
	}

	// Ensure the private passphrase is not empty.
	if len(privPassphrase) == 0 {
		str := "private passphrase may not be empty"
		return nil, lockerError(ErrEmptyPassphrase, str, nil)
	}

	// Perform the initial bucket creation and database namespace setup.
	if err := createLockerNS(namespace); err != nil {
		return nil, err
	}

	if config == nil {
		config = &DefaultScryptOptions
	}

	// Generate the BIP0044 HD key structure to ensure the provided seed
	// can generate the required structure with no issues.


	// Generate new master keys.  These master keys are used to protect the
	// crypto keys that will be generated next.
	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
	if err != nil {
		str := "failed to master public key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	masterKeyPriv, err := newSecretKey(&privPassphrase, config)
	if err != nil {
		str := "failed to master private key"
		return nil, lockerError(ErrCrypto, str, err)
	}

	// Generate the private  passphrase salt.  This is used when hashing
	// passwords to detect whether an unlock can be avoided when the locker
	// is already unlocked.
	var privPassphraseSalt [saltSize]byte
	_, err = rand.Read(privPassphraseSalt[:])
	if err != nil {
		str := "failed to read random source for passphrase salt"
		return nil, lockerError(ErrCrypto, str, err)
	}

	// Generate new crypto public, private, and script keys.  These keys are
	// used to protect the actual public and private data such as addresses,
	// extended keys, and scripts.
	cryptoKeyPub, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto public key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	cryptoKeyPriv, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto private key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	cryptoKeyScript, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto script key"
		return nil, lockerError(ErrCrypto, str, err)
	}

	// Encrypt the crypto keys with the associated master keys.
	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	if err != nil {
		str := "failed to encrypt crypto public key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	cryptoKeyPrivEnc, err := masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
	if err != nil {
		str := "failed to encrypt crypto private key"
		return nil, lockerError(ErrCrypto, str, err)
	}
	cryptoKeyScriptEnc, err := masterKeyPriv.Encrypt(cryptoKeyScript.Bytes())
	if err != nil {
		str := "failed to encrypt crypto script key"
		return nil, lockerError(ErrCrypto, str, err)
	}


	// Use the genesis block for the passed chain as the created at block
	// for the default.
	createdAt := &BlockStamp{Hash: *chainParams.GenesisHash, Height: 0}

	// Create the initial sync state.
	recentHashes := []wire.ShaHash{createdAt.Hash}
	recentHeight := createdAt.Height
	syncInfo := newSyncState(createdAt, createdAt, recentHeight, recentHashes)

	// Perform all database updates in a single transaction.
	err = namespace.Update(func(tx walletdb.Tx) error {
		// Save the master key params to the database.
		pubParams := masterKeyPub.Marshal()
		privParams := masterKeyPriv.Marshal()
		err = putMasterKeyParams(tx, pubParams, privParams)
		if err != nil {
			return err
		}

		// Save the encrypted crypto keys to the database.
		err = putCryptoKeys(tx, cryptoKeyPubEnc, cryptoKeyPrivEnc,
			cryptoKeyScriptEnc)
		if err != nil {
			return err
		}

		// Save the initial synced to state.
		err = putSyncedTo(tx, &syncInfo.syncedTo)
		if err != nil {
			return err
		}
		err = putStartBlock(tx, &syncInfo.startBlock)
		if err != nil {
			return err
		}

		// Save the initial recent blocks state.
		err = putRecentBlocks(tx, recentHeight, recentHashes)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// The new address locker is locked by default, so clear the master,
	// crypto private, crypto script and cointype keys from memory.
	masterKeyPriv.Zero()
	cryptoKeyPriv.Zero()
	cryptoKeyScript.Zero()
	return newLocker(namespace, masterKeyPub, masterKeyPriv,
		cryptoKeyPub, cryptoKeyPrivEnc, cryptoKeyScriptEnc, syncInfo,
		privPassphraseSalt), nil
}
