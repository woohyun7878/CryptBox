package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).

	// Private key used to decrypting data that is encrypted by the public encryption key.
	PrivateKey userlib.PKEDecKey
	// Sign key to create Digital Signatures, verified by public verification key.
	SignKey userlib.DSSignKey
	// Array of bytes for master key.
	MasterKey []byte
}

// Type definition for DataPair struct.
type DataPair struct {
	// Array of bytes holding the encrypted data.
	CipherText []byte
	// Array of HMAC or Digital Signature bytes for authentication.
	AuthBytes []byte
}

// Type definition for FileRoot struct.
type FileRoot struct {
	// UUID of last appended <FileNode, HMAC> pair.
	LastNodeUUID uuid.UUID
	// Decrypt key for data pointed by LastNodeUUID.
	LastDecryptKey []byte
	// MAC key for data pointed by LastNodeUUID.
	LastMACKey []byte
	// UUID of the first appended <FileNode, HMAC> pair.
	FirstNodeUUID uuid.UUID
	// Decrypt key for data pointed by FirstNodeUUID.
	FirstDecryptKey []byte
	// MAC key for data pointed by FirstNodeUUID.
	FirstMACKey []byte
	// List of Collaborators with whom the owner directly shared the file with
	Collaborators []string
}

// Type definition for FileNode struct.
type FileNode struct {
	// UUID of the next appended <FileNode, HMAC> pair.
	NextNodeUUID uuid.UUID
	// Decrypt key for data pointed by NextNodeUUID.
	NextDecryptKey []byte
	// MAC key for data pointed by NextNodeUUID.
	NextMACKey []byte
	// UUID of the corresponding <FileNode, HMAC> pair for the content.
	ContentUUID uuid.UUID
	// Decrypt key for data pointed by ContentUUID.
	ContentDecryptKey []byte
	// MAC key for data pointed by ContentUUID.
	ContentMACKey []byte
}

// Type definition for LockBox struct.
type LockBox struct {
	// Determines whether this LockBox directly links to the FileRoot or another LockBox.
	IsLayer bool
	// UUID of the <FileNode, HMAC> pair for the data.
	DataUUID uuid.UUID
	// Decrypt key for data pointed by DataUUID.
	DataDecryptKey []byte
	// MAC key for data pointed by DataUUID.
	DataMACKey []byte
}

// Type definition for Inivitation struct.
type Invitation struct {
	// UUID of the <FileNode, HMAC> pair for the LockBox or the LayerBox.
	UUID uuid.UUID
	// Decrypt key for data pointed by UUID.
	DecryptKey []byte
	// MAC key for data pointed by UUID.
	MACKey []byte
}

// Encrypt and MAC an array of bytes, using HashKDF and masterKey.
// Return ciphertext and MAC
func EncryptAndMacAndStore(content []byte) (ContentUUID userlib.UUID,
	encKey []byte, authKey []byte, err error) {
	// Get the UUID of the cipherText
	ContentUUID = uuid.New()
	// Create random encryptKey
	encryptKey := userlib.RandomBytes(16)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	// Get the authentication key to MAC the content
	macKey := userlib.RandomBytes(16)
	// Encrypt, MAC, and Store the content using the generated parameters
	err = CustomEncryptAndMacAndStore(ContentUUID, encryptKey, macKey, content)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	return ContentUUID, encryptKey, macKey, nil
}

// Encrypt and MAC an array of bytes, using HashKDF and masterKey.
// Return ciphertext and MAC
func CustomEncryptAndMacAndStore(ContentUUID userlib.UUID, encryptKey []byte,
	macKey []byte, content []byte) (
	err error) {
	iv := userlib.RandomBytes(16)
	// Encrypt the data using the EncryptKey
	cipherText := userlib.SymEnc(encryptKey, iv, content)
	// Get the MAC of the cipherText
	authBytes, err := userlib.HMACEval(macKey, cipherText)
	if err != nil {
		return err
	}
	// Create a new DataPair with <cipherText, contentMac>
	var contentDataPair DataPair
	contentDataPair.CipherText = cipherText
	contentDataPair.AuthBytes = authBytes
	// Marshal the contentDataPair
	contentBytes, err := json.Marshal(contentDataPair)
	// Upload the contentBytes to the generated UUID
	userlib.DatastoreSet(ContentUUID, contentBytes)
	// Return the UUID, Encryption Key, and MAC Key
	return nil
}

// Authenticate and Decrypt a userDataPair stored at the given UUID.
// Return ciphertext and MAC
func UserAuthandDecrypt(uuid userlib.UUID, masterKey []byte) (content []byte, err error) {
	// Get the datapairbytes from datastore
	userDataPairBytes, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return nil, errors.New("DatastoreGet failed at GetUser")
	}
	// Unmarshal the bytes into a DataPair
	var userDataPair DataPair
	err = json.Unmarshal(userDataPairBytes, &userDataPair)
	if err != nil {
		return nil, err
	}
	// Get the authentication key to MAC the content
	MACKey, err := userlib.HashKDF(masterKey, []byte("UserDataMACKey"))
	MACKey = MACKey[:16]
	if err != nil {
		return nil, err
	}
	// Get the MAC of the cipherText
	var checkMac []byte
	checkMac, err = userlib.HMACEval(MACKey, userDataPair.CipherText)
	if err != nil {
		return nil, err
	}
	// Check the MAC equals
	if !userlib.HMACEqual(checkMac, userDataPair.AuthBytes) {
		return nil, errors.New("MAC Failed at UserAuthandDecrypt")
	}
	// Get the decryption key to decrypt the content
	decryptKey, err := userlib.HashKDF(masterKey, []byte("UserDataEncryptionKey"))
	if err != nil {
		return nil, err
	}
	decryptKey = decryptKey[:16]
	// Decrypt the cipherText to content
	content = userlib.SymDec(decryptKey, userDataPair.CipherText)
	return content, nil
}

// Authenticate and Decrypt a DataPair given UUID, encKey, and macKey,
func authAndDecrypt(uuid userlib.UUID, encKey []byte, macKey []byte) (content []byte, err error) {
	// Get the datapairbytes from datastore
	DataPairBytes, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return nil, errors.New("DatastoreGet failed")
	}
	// Unmarshal the bytes into a DataPair
	var thisDataPair DataPair
	err = json.Unmarshal(DataPairBytes, &thisDataPair)
	if err != nil {
		return nil, err
	}
	// Get the MAC of the cipherText
	var checkMac []byte
	checkMac, err = userlib.HMACEval(macKey, thisDataPair.CipherText)
	if err != nil {
		return nil, err
	}
	// Check the MAC equals
	if !userlib.HMACEqual(checkMac, thisDataPair.AuthBytes) {
		return nil, errors.New("MAC or Ciphertext was tempered with!")
	}
	// Get the decryption key to decrypt the content
	content = userlib.SymDec(encKey, thisDataPair.CipherText)
	return content, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check username has length greater than zero
	if len(username) == 0 {
		return nil, errors.New("Username cannot be length of zero")
	}
	var userdata User
	userdata.Username = username
	// Create public encryption and decryption key
	var PubEncKey userlib.PKEEncKey
	var PubDecKey userlib.PKEDecKey
	PubEncKey, PubDecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	// Set PrivateKey to the generated decryption key
	userdata.PrivateKey = PubDecKey
	// Create public sign and verification key

	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	// Set SignKey to the generated sign key
	userdata.SignKey = DSSignKey
	// Create master key
	userdata.MasterKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	// Hash the username and deterministically derive the UUID
	var userUUID userlib.UUID
	userUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// Check if data exists in this UUID already
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("Username exists already")
	}
	// Upload the public encryption key to keystore under "username + pubKey"
	userlib.KeystoreSet(username+"pubKey", PubEncKey)
	// Upload the public sign key to keystore under "username + signKey"
	userlib.KeystoreSet(username+"signKey", DSVerifyKey)
	// Convert userdata into array of bytes
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	// Use hashKDF to derive the user encryption key
	encKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserDataEncryptionKey"))
	if err != nil {
		return nil, err
	}
	encKey = encKey[:16]
	// Get the iv from RandomBytes
	iv := userlib.RandomBytes(16)
	// Encrypt userBytes using encKey
	cipherText := userlib.SymEnc(encKey, iv, userBytes)
	// Use hashKDF to derive the user MAC key
	authKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserDataMACKey"))
	if err != nil {
		return nil, err
	}
	authKey = authKey[:16]
	// MAC the cipherText using authKey
	userMAC, err := userlib.HMACEval(authKey, cipherText)
	var userDataPair DataPair
	userDataPair.CipherText = cipherText
	userDataPair.AuthBytes = userMAC
	// Convert the userDataPair into array of bytes
	userDataPairBytes, err := json.Marshal(userDataPair)
	if err != nil {
		return nil, err
	}
	// Store the userDataPairBytes in DataStore at userUUID
	userlib.DatastoreSet(userUUID, userDataPairBytes)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	// Create master key
	var masterKey []byte
	masterKey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	// Hash the username and deterministically derive the UUID
	var userUUID userlib.UUID
	userUUID, err = uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	userBytes, err := UserAuthandDecrypt(userUUID, masterKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(userBytes, userdataptr)
	if err != nil {
		return nil, err
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	_, _, _, err = userdata.storeFileAndGetRootInfo(filename, content)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) storeFileAndGetRootInfo(filename string, content []byte) (ContentUUID userlib.UUID, encryptKey []byte,
	macKey []byte, err error) {
	// User.MasterKey
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	userFileMasterKey = userFileMasterKey[:16]
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	thisFileKey = thisFileKey[:16]
	thisFileBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	thisFileBytes = thisFileBytes[:16]
	thisFileUUID, err := uuid.FromBytes(thisFileBytes)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	thisFileMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	thisFileMACKey = thisFileMACKey[:16]
	thisFileEncKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	thisFileEncKey = thisFileEncKey[:16]
	_, ok := userlib.DatastoreGet(thisFileUUID)
	if !ok {
		// if fileName DNE in personal namespace
		_uuid, encKey, macKey, err := EncryptAndMacAndStore(content)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		fileNode := FileNode{
			ContentUUID:       _uuid,
			ContentDecryptKey: encKey,
			ContentMACKey:     macKey,
		}
		fileNodeBytes, err := json.Marshal(fileNode)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		_uuid, encKey, macKey, err = EncryptAndMacAndStore(fileNodeBytes)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		fileRoot := FileRoot{
			FirstNodeUUID:   _uuid,
			LastNodeUUID:    _uuid,
			FirstMACKey:     macKey,
			LastMACKey:      macKey,
			FirstDecryptKey: encKey,
			LastDecryptKey:  encKey,
		}
		fileRootBytes, err := json.Marshal(fileRoot)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		rootUUID, rootEncKey, rootMacKey, err := EncryptAndMacAndStore(fileRootBytes)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		lockBox := LockBox{
			IsLayer:        false,
			DataUUID:       rootUUID,
			DataDecryptKey: rootEncKey,
			DataMACKey:     rootMacKey,
		}
		lockBoxBytes, err := json.Marshal(lockBox)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		iv := userlib.RandomBytes(16)
		cipherText := userlib.SymEnc(thisFileEncKey, iv, lockBoxBytes)
		authBytes, err := userlib.HMACEval(thisFileMACKey, cipherText)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		boxPair := DataPair{
			CipherText: cipherText,
			AuthBytes:  authBytes,
		}
		boxBytes, err := json.Marshal(boxPair)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		userlib.DatastoreSet(thisFileUUID, boxBytes)
		return rootUUID, rootEncKey, rootMacKey, nil
	} else {
		// if fileName exists in personal namespace
		boxBytes, err := authAndDecrypt(thisFileUUID, thisFileEncKey, thisFileMACKey)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		var box LockBox
		err = json.Unmarshal(boxBytes, &box)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		for box.IsLayer {
			nextBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
			if err != nil {
				return uuid.Nil, nil, nil, err
			}
			err = json.Unmarshal(nextBytes, &box)
			if err != nil {
				return uuid.Nil, nil, nil, err
			}
		}
		var fileRoot FileRoot
		fileRootBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
		ogUUID, ogDecKey, ogMACKey := box.DataUUID, box.DataDecryptKey, box.DataMACKey
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		err = json.Unmarshal(fileRootBytes, &fileRoot)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		_uuid, encKey, macKey, err := EncryptAndMacAndStore(content)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		fileNode := FileNode{
			ContentUUID:       _uuid,
			ContentDecryptKey: encKey,
			ContentMACKey:     macKey,
		}
		fileNodeBytes, err := json.Marshal(fileNode)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		_uuid, encKey, macKey, err = EncryptAndMacAndStore(fileNodeBytes)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		fileRoot.LastNodeUUID, fileRoot.FirstNodeUUID = _uuid, _uuid
		fileRoot.LastDecryptKey, fileRoot.FirstDecryptKey = encKey, encKey
		fileRoot.LastMACKey, fileRoot.FirstMACKey = macKey, macKey
		fileRootBytes, err = json.Marshal(fileRoot)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		err = CustomEncryptAndMacAndStore(ogUUID, ogDecKey, ogMACKey, fileRootBytes)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		return ogUUID, ogDecKey, ogMACKey, nil
	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return err
	}
	userFileMasterKey = userFileMasterKey[:16]
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return err
	}
	thisFileKey = thisFileKey[:16]
	thisFileBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return err
	}
	thisFileBytes = thisFileBytes[:16]
	thisFileUUID, err := uuid.FromBytes(thisFileBytes)
	if err != nil {
		return err
	}
	thisFileMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return err
	}
	thisFileMACKey = thisFileMACKey[:16]
	thisFileEncKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return err
	}
	thisFileEncKey = thisFileEncKey[:16]

	boxBytes, err := authAndDecrypt(thisFileUUID, thisFileEncKey, thisFileMACKey)
	if err != nil {
		// file DNE in personal namespace, so throw an error
		return err
	}

	var box LockBox
	err = json.Unmarshal(boxBytes, &box)
	if err != nil {
		return err
	}
	for box.IsLayer {
		nextBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
		if err != nil {
			return err
		}
		err = json.Unmarshal(nextBytes, &box)
		if err != nil {
			return err
		}
	}
	var fileRoot FileRoot
	fileRootBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileRootBytes, &fileRoot)
	if err != nil {
		return err
	}

	// create new fileNode
	uuid, encKey, macKey, err := EncryptAndMacAndStore(content)
	if err != nil {
		return err
	}
	fileNode := FileNode{
		ContentUUID:       uuid,
		ContentDecryptKey: encKey,
		ContentMACKey:     macKey,
	}
	fileNodeBytes, err := json.Marshal(fileNode)
	if err != nil {
		return err
	}
	uuid, encKey, macKey, err = EncryptAndMacAndStore(fileNodeBytes)
	if err != nil {
		return err
	}

	// previous last node of the linked list
	var lastNode FileNode
	lastNodeBytes, err := authAndDecrypt(fileRoot.LastNodeUUID, fileRoot.LastDecryptKey, fileRoot.LastMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(lastNodeBytes, &lastNode)
	if err != nil {
		return err
	}

	// update keys and pointers in the previous last node
	lastNode.NextNodeUUID = uuid
	lastNode.NextDecryptKey = encKey
	lastNode.NextMACKey = macKey
	prevLastNodeContent, err := json.Marshal(lastNode)
	if err != nil {
		return err
	}

	// re-encrypt the previously last node with its original encryption
	err = CustomEncryptAndMacAndStore(fileRoot.LastNodeUUID, fileRoot.LastDecryptKey, fileRoot.LastMACKey, prevLastNodeContent)
	if err != nil {
		return err
	}

	// update fileRoot
	fileRoot.LastNodeUUID = uuid
	fileRoot.LastDecryptKey = encKey
	fileRoot.LastMACKey = macKey
	updatedFileRootBytes, err := json.Marshal(fileRoot)
	if err != nil {
		return err
	}

	// re-encrypt with original encryption
	err = CustomEncryptAndMacAndStore(box.DataUUID, box.DataDecryptKey, box.DataMACKey, updatedFileRootBytes)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return nil, err
	}
	userFileMasterKey = userFileMasterKey[:16]
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return nil, err
	}
	thisFileKey = thisFileKey[:16]
	thisFileBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return nil, err
	}
	thisFileBytes = thisFileBytes[:16]
	thisFileUUID, err := uuid.FromBytes(thisFileBytes)
	if err != nil {
		return nil, err
	}
	thisFileMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return nil, err
	}
	thisFileMACKey = thisFileMACKey[:16]
	thisFileEncKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return nil, err
	}
	thisFileEncKey = thisFileEncKey[:16]

	boxBytes, err := authAndDecrypt(thisFileUUID, thisFileEncKey, thisFileMACKey)
	if err != nil {
		// file DNE in personal namespace, so throw an error
		return nil, err
	}

	var box LockBox
	err = json.Unmarshal(boxBytes, &box)
	if err != nil {
		return nil, err
	}
	for box.IsLayer {
		nextBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(nextBytes, &box)
		if err != nil {
			return nil, err
		}
	}
	var fileRoot FileRoot
	fileRootBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(fileRootBytes, &fileRoot)
	if err != nil {
		return nil, err
	}
	var curNode FileNode
	curNodeBytes, err := authAndDecrypt(fileRoot.FirstNodeUUID, fileRoot.FirstDecryptKey, fileRoot.FirstMACKey)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(curNodeBytes, &curNode)
	if err != nil {
		return nil, err
	}
	var returnContent []byte
	for curNode.ContentUUID != uuid.Nil {
		contentBytes, err := authAndDecrypt(curNode.ContentUUID, curNode.ContentDecryptKey, curNode.ContentMACKey)
		if err != nil {
			return nil, err
		}
		returnContent = append(returnContent, contentBytes...)
		if curNode.NextNodeUUID == uuid.Nil {
			break
		}
		nextBytes, err := authAndDecrypt(curNode.NextNodeUUID, curNode.NextDecryptKey, curNode.NextMACKey)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(nextBytes, &curNode)
		if err != nil {
			return nil, err
		}
	}
	return returnContent, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// You cannot invite yourself
	if recipientUsername == userdata.Username {
		return uuid.Nil, errors.New("cannot invite yourself")
	}
	_, ok := userlib.KeystoreGet(recipientUsername + "pubKey")
	if !ok {
		return uuid.Nil, errors.New("cannot create invitation for nonexistent user")
	}
	// Get userFileMasterKey through hashKDF and MasterKey
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return uuid.Nil, err
	}
	userFileMasterKey = userFileMasterKey[:16]
	// Get thisFileKey through hashKDF and thisFileKey
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return uuid.Nil, err
	}
	thisFileKey = thisFileKey[:16]
	// Get UUID, decryptKey, and macKey for this file
	lockUUIDBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return uuid.Nil, err
	}
	lockUUIDBytes = lockUUIDBytes[:16]
	lockUUID, err := uuid.FromBytes(lockUUIDBytes)
	if err != nil {
		return uuid.Nil, err
	}
	lockDecryptKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return uuid.Nil, err
	}
	lockDecryptKey = lockDecryptKey[:16]
	lockMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return uuid.Nil, err
	}
	lockMACKey = lockMACKey[:16]
	// Get the DataPair for the LockBox for this file
	lockBoxDataPairBytes, ok := userlib.DatastoreGet(lockUUID)
	if !ok {
		return uuid.Nil, err
	}
	var lockBoxDataPair DataPair
	err = json.Unmarshal(lockBoxDataPairBytes, &lockBoxDataPair)
	if err != nil {
		return uuid.Nil, err
	}
	// Calculate the MAC of this cipherText
	var checkMac []byte
	checkMac, err = userlib.HMACEval(lockMACKey, lockBoxDataPair.CipherText)
	if err != nil {
		return uuid.Nil, err
	}
	// Check the MAC equals
	if !userlib.HMACEqual(checkMac, lockBoxDataPair.AuthBytes) {
		return uuid.Nil, errors.New("MAC Failed at UserAuthandDecrypt")
	}
	// Decrypt the LockBox
	lockBoxBytes := userlib.SymDec(lockDecryptKey, lockBoxDataPair.CipherText)
	var lockBox LockBox
	err = json.Unmarshal(lockBoxBytes, &lockBox)
	if err != nil {
		return uuid.Nil, err
	}
	// Create a new invBox for the recipient
	var invBox LockBox
	if !lockBox.IsLayer {
		// If lockBox.IsLayer is false, the user is the owner
		// Copy over details INSIDE the lockBox
		// Send a LockBox
		invBox.DataUUID = lockBox.DataUUID
		invBox.DataDecryptKey = lockBox.DataDecryptKey
		invBox.DataMACKey = lockBox.DataMACKey
		invBox.IsLayer = false
		fileRootBytes, err := authAndDecrypt(lockBox.DataUUID,
			lockBox.DataDecryptKey, lockBox.DataMACKey)
		if err != nil {
			return uuid.Nil, err
		}
		var fileRoot FileRoot
		err = json.Unmarshal(fileRootBytes, &fileRoot)
		if err != nil {
			return uuid.Nil, err
		}
		// Append the userName to the Collaborators list

		fileRoot.Collaborators = append(fileRoot.Collaborators, recipientUsername)

		// Marshal the updated fileRoot
		updatedFileRootBytes, err := json.Marshal(fileRoot)
		if err != nil {
			return uuid.Nil, err
		}
		// Encrypt and MAC and Store the fileRoot, using same UUID and keys in the box
		err = CustomEncryptAndMacAndStore(lockBox.DataUUID, lockBox.DataDecryptKey,
			lockBox.DataMACKey, updatedFileRootBytes)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		// Else, the user is not the owner
		// Check access to the lockBox (layer before fileRoot) is still available.
		for lockBox.IsLayer {
			nextBytes, err := authAndDecrypt(lockBox.DataUUID, lockBox.DataDecryptKey, lockBox.DataMACKey)
			if err != nil {
				return uuid.Nil, err
			}
			err = json.Unmarshal(nextBytes, &lockBox)
			if err != nil {
				return uuid.Nil, err
			}
		}
		// Copy over details TO ths lockBox
		// Send a LayerBox
		invBox.DataUUID = lockUUID
		invBox.DataDecryptKey = lockDecryptKey
		invBox.DataMACKey = lockMACKey
		invBox.IsLayer = true
	}
	// Generate and assign the EncryptKey for the invBox through hashKDF and thisFileKey
	invBoxEncryptKey, err := userlib.HashKDF(thisFileKey,
		[]byte(recipientUsername+"invBoxEncryptKey"))
	if err != nil {
		return uuid.Nil, err
	}
	invBoxEncryptKey = invBoxEncryptKey[:16]
	// Marshal the invBox
	invBoxBytes, err := json.Marshal(invBox)
	if err != nil {
		return uuid.Nil, err
	}
	// Encrypt the invBoxBytes.
	iv := userlib.RandomBytes(16)
	invBoxCipherText := userlib.SymEnc(invBoxEncryptKey, iv, invBoxBytes)
	// Generate invMACKey
	invMACKey, err := userlib.HashKDF(thisFileKey,
		[]byte(recipientUsername+"invBoxMACKey"))
	if err != nil {
		return uuid.Nil, err
	}
	invMACKey = invMACKey[:16]
	// MAC invBoxCipherText
	invBoxAuthBytes, err := userlib.HMACEval(invMACKey, invBoxCipherText)
	if err != nil {
		return uuid.Nil, err
	}
	// Generate invBoxDataPair
	var invBoxDataPair DataPair
	invBoxDataPair.CipherText = invBoxCipherText
	invBoxDataPair.AuthBytes = invBoxAuthBytes
	// Generate the UUID for invBox
	invUUIDBytes, err := userlib.HashKDF(thisFileKey,
		[]byte(recipientUsername+"invBoxUUID"))
	if err != nil {
		return uuid.Nil, err
	}
	invUUIDBytes = invUUIDBytes[:16]
	invUUID, err := uuid.FromBytes(invUUIDBytes)
	if err != nil {
		return uuid.Nil, err
	}
	// Marshal invBoxDataPair
	invBoxDataPairBytes, err := json.Marshal(invBoxDataPair)
	if err != nil {
		return uuid.Nil, err
	}
	// Store the invBoxDataPair at the invUUID
	userlib.DatastoreSet(invUUID, invBoxDataPairBytes)
	// Create a new invitation
	var invitation Invitation
	invitation.UUID = invUUID
	invitation.DecryptKey = invBoxEncryptKey
	invitation.MACKey = invMACKey
	// Get the public key of the recipient through keystore
	recipientKey, ok := userlib.KeystoreGet(recipientUsername + "pubKey")
	if !ok {
		return uuid.Nil, err
	}
	// Encrypt the invitatin using recipientKey
	invitationBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	invitationCipherText, err := userlib.PKEEnc(recipientKey, invitationBytes)
	if err != nil {
		return uuid.Nil, err
	}
	// Generate Digital Signature for this invitation
	invitationSignature, err := userlib.DSSign(userdata.SignKey, invitationCipherText)
	if err != nil {
		return uuid.Nil, err
	}
	// Create a new DataPair for the invitation
	var invitationDataPair DataPair
	invitationDataPair.CipherText = invitationCipherText
	invitationDataPair.AuthBytes = invitationSignature
	// Marshal the invitationDataPair
	invitationDataPairBytes, err := json.Marshal(invitationDataPair)
	if err != nil {
		return uuid.Nil, err
	}
	// Create a random UUID for the invitation
	invitationUUID := uuid.New()
	// Store the invitationDataPair at this UUID
	userlib.DatastoreSet(invitationUUID, invitationDataPairBytes)
	// Return the UUID to the invitation
	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if senderUsername == userdata.Username {
		return errors.New("cannot accept invitation from yourself")
	}
	_, ok := userlib.KeystoreGet(senderUsername + "pubKey")
	if !ok {
		return errors.New("cannot accept invitation for nonexistent user")
	}
	// Get the <Encrypted Invitation, Signature> invitationDataPairBytes
	invitationDataPairBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("DatastoreGet failed at AcceptInvitation")
	}
	// Unmarshal the bytes into a DataPair instance
	var invitationDataPair DataPair
	err := json.Unmarshal(invitationDataPairBytes, &invitationDataPair)
	if err != nil {
		return err
	}
	// Get the signKey of the sender
	senderSignKey, ok := userlib.KeystoreGet(senderUsername + "signKey")
	if !ok {
		return errors.New("KeystoreGet failed at AcceptInvitation")
	}
	// Verify the signature of the invitation
	err = userlib.DSVerify(senderSignKey, invitationDataPair.CipherText,
		invitationDataPair.AuthBytes)
	if err != nil {
		return err
	}
	// Decrypt the cipherText with privateKey
	invitationBytes, err := userlib.PKEDec(userdata.PrivateKey, invitationDataPair.CipherText)
	if err != nil {
		return err
	}
	// Unmarshal the bytes into a Invitation instance
	var invitation Invitation
	err = json.Unmarshal(invitationBytes, &invitation)
	if err != nil {
		return err
	}
	// Get the box pointed by this invitation
	boxBytes, err := authAndDecrypt(invitation.UUID, invitation.DecryptKey,
		invitation.MACKey)
	if err != nil {
		return err
	}
	var box LockBox
	err = json.Unmarshal(boxBytes, &box)
	if err != nil {
		return err
	}
	// Create a new layerBox
	var layerBox LockBox
	// Copy over details from the invitation
	layerBox.DataUUID = invitation.UUID
	layerBox.DataDecryptKey = invitation.DecryptKey
	layerBox.DataMACKey = invitation.MACKey
	layerBox.IsLayer = true
	// Marshal the layerBox
	layerBoxBytes, err := json.Marshal(layerBox)
	if err != nil {
		return err
	}
	// Deterministically userFileMasterKey and thisFileKey using the masterKey
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return err
	}
	userFileMasterKey = userFileMasterKey[:16]
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return err
	}
	thisFileKey = thisFileKey[:16]
	// Deterministically derive thisFileUUID using thisFileKey
	thisFileBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return err
	}
	thisFileBytes = thisFileBytes[:16]
	thisFileUUID, err := uuid.FromBytes(thisFileBytes)
	if err != nil {
		return err
	}
	// Check if anything exists at this UUID. If so, throw an error.
	_, ok = userlib.DatastoreGet(thisFileUUID)
	if ok {
		return errors.New("filename already exists")
	}
	// Deterministically derive thisFileEncKey using thisFileKey
	thisFileEncKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return err
	}
	thisFileEncKey = thisFileEncKey[:16]
	// Deterministically derive thisFileMACKey using thisFileKey
	thisFileMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return err
	}
	thisFileMACKey = thisFileMACKey[:16]
	// Encrypt and MAC, and Store the layerBox using the parameters above
	err = CustomEncryptAndMacAndStore(thisFileUUID, thisFileEncKey,
		thisFileMACKey, layerBoxBytes)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if recipientUsername == userdata.Username {
		return errors.New("cannot revoke yourself")
	}
	_, ok := userlib.KeystoreGet(recipientUsername + "pubKey")
	if !ok {
		return errors.New("cannot revoke access for nonexistent user")
	}
	userFileMasterKey, err := userlib.HashKDF(userdata.MasterKey, []byte("UserFileMasterKey"))
	if err != nil {
		return err
	}
	userFileMasterKey = userFileMasterKey[:16]
	thisFileKey, err := userlib.HashKDF(userFileMasterKey, []byte(filename))
	if err != nil {
		return err
	}
	thisFileKey = thisFileKey[:16]
	thisFileBytes, err := userlib.HashKDF(thisFileKey, []byte("UUID"))
	if err != nil {
		return err
	}
	thisFileBytes = thisFileBytes[:16]
	thisFileUUID, err := uuid.FromBytes(thisFileBytes)
	if err != nil {
		return err
	}
	thisFileMACKey, err := userlib.HashKDF(thisFileKey, []byte("MAC"))
	if err != nil {
		return err
	}
	thisFileMACKey = thisFileMACKey[:16]
	thisFileEncKey, err := userlib.HashKDF(thisFileKey, []byte("Encrypt"))
	if err != nil {
		return err
	}
	thisFileEncKey = thisFileEncKey[:16]

	boxBytes, err := authAndDecrypt(thisFileUUID, thisFileEncKey, thisFileMACKey)
	if err != nil {
		// file DNE in personal namespace, so throw an error
		return err
	}

	var box LockBox
	err = json.Unmarshal(boxBytes, &box)
	if err != nil {
		return err
	}

	var fileRoot FileRoot
	fileRootBytes, err := authAndDecrypt(box.DataUUID, box.DataDecryptKey, box.DataMACKey)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileRootBytes, &fileRoot)
	if err != nil {
		return err
	}

	if len(fileRoot.Collaborators) == 0 {
		return errors.New("there are no direct collaborators for this file")
	}
	var removed bool
	// remove revoked collaborator from list
	for i, s := range fileRoot.Collaborators {
		if s == recipientUsername {
			fileRoot.Collaborators = append(fileRoot.Collaborators[:i], fileRoot.Collaborators[i+1:]...)
			collabUUIDBytes, err := userlib.HashKDF(thisFileKey,
				[]byte(recipientUsername+"invBoxUUID"))
			if err != nil {
				return err
			}
			collabUUIDBytes = collabUUIDBytes[:16]
			collabUUID, err := uuid.FromBytes(collabUUIDBytes)
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(collabUUID)
			removed = true
			break
		}
	}
	if !removed {
		return errors.New("collaborator does not exist")
	}
	updatedFileRootBytes, err := json.Marshal(fileRoot)
	if err != nil {
		return err
	}

	// re-encrypt the changed fileRoot using the original keys
	err = CustomEncryptAndMacAndStore(box.DataUUID, box.DataDecryptKey, box.DataMACKey, updatedFileRootBytes)
	if err != nil {
		return err
	}

	// obtain the original file
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// relocate and reencrypt the file using randomly generated keys
	newUUID, encKey, macKey, err := userdata.storeFileAndGetRootInfo(filename, content)
	if err != nil {
		return err
	}

	// change my lockBox attributes and re-encrypt using the original keys
	box.DataDecryptKey = encKey
	box.DataMACKey = macKey
	box.DataUUID = newUUID
	newBoxBytes, err := json.Marshal(box)
	if err != nil {
		return err
	}
	err = CustomEncryptAndMacAndStore(thisFileUUID, thisFileEncKey, thisFileMACKey, newBoxBytes)
	if err != nil {
		return err
	}

	// change every other collaborator's lockBox attributes and re-encrypt using the original keys
	for _, collaborator := range fileRoot.Collaborators {

		// deterministically derive the corresponding keys for the collaborator's layerbox
		invBoxEncryptKey, err := userlib.HashKDF(thisFileKey,
			[]byte(collaborator+"invBoxEncryptKey"))
		if err != nil {
			return err
		}
		invBoxEncryptKey = invBoxEncryptKey[:16]

		invBoxMACKey, err := userlib.HashKDF(thisFileKey,
			[]byte(collaborator+"invBoxMACKey"))
		if err != nil {
			return err
		}
		invBoxMACKey = invBoxMACKey[:16]

		invBoxUUIDBytes, err := userlib.HashKDF(thisFileKey,
			[]byte(collaborator+"invBoxUUID"))
		if err != nil {
			return err
		}
		invBoxUUIDBytes = invBoxUUIDBytes[:16]
		invBoxUUID, err := uuid.FromBytes(invBoxUUIDBytes)
		if err != nil {
			return err
		}

		// Get the collaborator lockbox from the datastore

		boxBytes, err := authAndDecrypt(invBoxUUID, invBoxEncryptKey, invBoxMACKey)
		if err != nil {
			// file DNE in personal namespace, so throw an error
			return err
		}

		var box LockBox
		err = json.Unmarshal(boxBytes, &box)
		if err != nil {
			return err
		}

		// change the collaborator lockbox's attributes to correspond to the relocated fileRoot
		box.DataDecryptKey = encKey
		box.DataMACKey = macKey
		box.DataUUID = newUUID
		newBoxBytes, err := json.Marshal(box)
		if err != nil {
			return err
		}
		err = CustomEncryptAndMacAndStore(invBoxUUID, invBoxEncryptKey, invBoxMACKey, newBoxBytes)
		if err != nil {
			return err
		}
	}
	return nil
}
