package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	"bytes"
	_ "encoding/hex"
	_ "errors"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test 1: Testing Username Uniqueness case sensitive", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing another user alice")
			alice2, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking Alice and alice are different users")
			Expect(alice).ToNot(Equal(alice2))
		})

		Specify("Custom Test 2: Testing Username Uniqueness", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing another user Alice")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test 3: Testing Username length is greater than zero", func() {
			userlib.DebugMsg("Initializing user with no username")
			alice, err = client.InitUser("", defaultPassword)
			userlib.DebugMsg("Checking program errors")
			Expect(err).ToNot(BeNil())
			alice, err = client.GetUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test 4: Testing password of length zero", func() {
			userlib.DebugMsg("Initializing user with password length of zero")
			alice, err = client.InitUser("Alice", "")
			Expect(err).To(BeNil())
			alice, err = client.GetUser("Alice", "")
			Expect(err).To(BeNil())
		})

		Specify("Custom Test 5: Testing same filename by different ursers", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice stores a file called Apple")
			err = alice.StoreFile("Apple", []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("Bob", defaultPassword)
			userlib.DebugMsg("Bob also stores a file called Apple but with different content")
			err = bob.StoreFile("Apple", []byte(contentTwo))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Alice loads her Apple")
			aliceApple, err := alice.LoadFile("Apple")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check Alice's apple is hers")
			Expect(aliceApple).To(Equal([]byte(contentOne)))
			userlib.DebugMsg("Bob loads his Apple")
			bobApple, err := bob.LoadFile("Apple")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Check Bob's apple is his")
			Expect(bobApple).To(Equal([]byte(contentTwo)))
		})

		Specify("Custom Test 6: Testing confidentiality", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			// Save user data into dMap1
			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}
			userlib.DebugMsg("Alice stores a file called Apple")
			err = alice.StoreFile("Apple", []byte(contentOne))
			Expect(err).To(BeNil())
			// Get the updated data in dMap2
			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap2[key] = val
			}
			// Delete the user data, keeping just the file data
			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}
			// Clear the DataStore
			userlib.DatastoreClear()
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			// Save user data into dMap1
			dMap = userlib.DatastoreGetMap()
			dMap3 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap3[key] = val
			}
			// Repeat the process
			err = alice.StoreFile("Apple", []byte(contentOne))
			Expect(err).To(BeNil())
			// Get the updated data in dMap2
			dMap = userlib.DatastoreGetMap()
			dMap4 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap4[key] = val
			}
			// Delete the user data, keeping just the file data
			for key, _ := range dMap4 {
				if _, ok := dMap3[key]; ok {
					delete(dMap4, key)
				}
			}
			userlib.DebugMsg("Checking storing file twice does not encrypt the same way")
			Expect(dMap2).ToNot(Equal(dMap4))

			for key, _ := range dMap4 {
				userlib.DatastoreDelete(key)
			}
			_, err = alice.LoadFile("Apple")
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Checking number of keys in keystore consistency", func() {
			userlib.DebugMsg("Checking number of keys in keystore consistency")
			charlie, err := client.InitUser("Charlie", defaultPassword)
			Expect(err).To(BeNil())
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("file1.txt", []byte(contentOne))
			Expect(err).To(BeNil())
			kMap := userlib.KeystoreGetMap()
			kMap1 := make(map[string]userlib.PublicKeyType)
			for key, val := range kMap {
				kMap1[key] = val
			}
			alice.StoreFile("file2.txt", []byte(contentOne))
			alice.StoreFile("file3.txt", []byte(contentOne))
			alice.StoreFile("file4.txt", []byte(contentOne))
			alice.StoreFile("file5.txt", []byte(contentOne))
			charlieInv, err := alice.CreateInvitation("file1.txt", "Charlie")
			Expect(err).To(BeNil())
			charlie.AcceptInvitation("Alice", charlieInv, "charlieFile")
			kMap = userlib.KeystoreGetMap()
			kMap2 := make(map[string]userlib.PublicKeyType)
			for key, val := range kMap {
				kMap2[key] = val
			}
			Expect(len(kMap1)).To(Equal(len(kMap2)))
		})
		// Helper function to measure bandwidth of a particular operation
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		Specify("Custom Test: Bandwidth test", func() {
			userlib.DebugMsg("Custom Test: Bandwidth test")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
			alice.StoreFile("file1.txt", []byte(contentOne))
			Expect(err).To(BeNil())
			bw := measureBandwidth(func() {
				alice.AppendToFile("file1.txt", []byte(contentOne))
			})
			for i := 1; i < 10000; i++ {
				newBw := measureBandwidth(func() {
					alice.AppendToFile("file1.txt", []byte(contentOne))
				})
				diff := newBw - bw
				Expect(diff < 2).To(BeTrue())
			}
			for i := 1; i < 1000; i++ {
				newBw := measureBandwidth(func() {
					alice.AppendToFile("file1.txt", bytes.Repeat([]byte(contentOne), i))
				})
				Expect((newBw - bw*i) < 2).To(BeTrue())
			}
			for i := 1; i < 100; i++ {
				bot, err := client.InitUser("bot"+strconv.Itoa(i), defaultPassword)
				Expect(err).To(BeNil())
				botInv, err := alice.CreateInvitation("file1.txt", "bot"+strconv.Itoa(i))
				Expect(err).To(BeNil())
				err = bot.AcceptInvitation("Alice", botInv, "botfile")
				newBw := measureBandwidth(func() {
					alice.AppendToFile("file1.txt", []byte(contentOne))
				})
				diff := newBw - bw*i
				Expect(diff < 10).To(BeTrue())
			}
		})

		Specify("Custom Test: Sharing with two users and revoking one", func() {
			userlib.DebugMsg("Custom Test: Sharing with two users and revoking one")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("wrongName", invite, bobFile)
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can still load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

		})

		Specify("Custom Test: testing multiple users having the same password", func() {
			userlib.DebugMsg("Custom Test: testing multiple users having the same password")
			_, err := client.InitUser("Bob", "password")
			Expect(err).To(BeNil())
			_, err = client.InitUser("Alice", "password")
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: getting files that don't exist should error", func() {
			userlib.DebugMsg("Custom Test: getting files that don't exist should error")
			bad_user, bad_password := "Idont", "exist"
			IDontExist, err := client.GetUser(bad_user, bad_password)
			Expect(err).ToNot(BeNil())
			Expect(IDontExist).To(BeNil())
		})

		Specify("Custom Test: client should detect wrong passwords", func() {
			userlib.DebugMsg("Custom Test: client should detect wrong passwords")
			bad_user, bad_password := "Idont", "exist"
			client.InitUser(bad_user, bad_password)
			bob, err := client.GetUser(bad_user, "wrongpassword")
			Expect(err).ToNot(BeNil())
			Expect(bob).To(BeNil())
		})

		Specify("Custom Test: Testing integrity of invitation", func() {
			userlib.DebugMsg("Custom Test: Testing integrity of invitation")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)

			for key, val := range dMap {
				dMap2[key] = val
			}

			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}

			for key, _ := range dMap2 {
				userlib.DatastoreSet(key, []byte("Mallory messed with this"))
			}

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Testing integrity of invitation 2", func() {
			userlib.DebugMsg("Custom Test: Testing integrity of invitation 2")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			kMap := userlib.KeystoreGetMap()
			kMap1 := make(map[string]userlib.PublicKeyType)
			for key, val := range kMap {
				kMap1[key] = val
			}
			userlib.KeystoreClear()

			_, malKey, err := userlib.DSKeyGen()

			for key, _ := range kMap1 {
				userlib.KeystoreSet(key, malKey)
			}

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing integrity of invitation 3", func() {
			userlib.DebugMsg("Custom Test: Testing integrity of invitation 3")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)

			for key, val := range dMap {
				dMap2[key] = val
			}

			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}

			for key, _ := range dMap2 {
				userlib.DatastoreSet(key, []byte("Mallory messed with this"))
			}

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Testing integrity of file", func() {
			userlib.DebugMsg("Custom Test: Testing integrity of file")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap2[key] = val
			}

			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}

			for key, val := range dMap2 {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, append(val, byte(1)))
			}

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality of file", func() {
			userlib.DebugMsg("Custom Test: Testing integrity of file")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile("file1", []byte(contentOne))

			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap2[key] = val
			}

			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}

			err = alice.StoreFile("file2", []byte(contentOne))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile("file2")
			Expect(bytes.Equal(data, []byte(contentOne))).To(BeTrue())

			dMap = userlib.DatastoreGetMap()
			dMap3 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap3[key] = val
			}

			for key, _ := range dMap3 {
				if _, ok := dMap1[key]; ok {
					delete(dMap3, key)
				}
				if _, ok := dMap2[key]; ok {
					delete(dMap3, key)
				}
			}

			for _, value3 := range dMap3 {
				Expect(bytes.Equal(value3, []byte(contentOne))).To(BeFalse())
				for _, value2 := range dMap2 {
					Expect(bytes.Equal(value2, value3)).To(BeFalse())
					Expect(bytes.Equal(value2, []byte(contentOne))).To(BeFalse())
				}
			}

			charlie, err := client.InitUser("Charlie", defaultPassword)
			Expect(err).To(BeNil())
			charlieInv, err := alice.CreateInvitation("file2", "Charlie")
			Expect(err).To(BeNil())
			err = charlie.AcceptInvitation("alice", charlieInv, "charlieFile")
			Expect(err).To(BeNil())
			data, err = charlie.LoadFile("charlieFile")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(data, []byte(contentOne))).To(BeTrue())
			err = charlie.AppendToFile("charlieFile", []byte(contentTwo))
			Expect(err).To(BeNil())
			dMap = userlib.DatastoreGetMap()
			dMap4 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap4[key] = val
			}
			for key, _ := range dMap4 {
				if _, ok := dMap1[key]; ok {
					delete(dMap4, key)
				}
				if _, ok := dMap2[key]; ok {
					delete(dMap4, key)
				}
				if _, ok := dMap3[key]; ok {
					delete(dMap4, key)
				}
			}
			// Charlie trying to revoke, when he is not the owner
			err = charlie.RevokeAccess("charlieFile", "alice")
			Expect(err).ToNot(BeNil())
			err = alice.RevokeAccess("file2", "Charlie")
			Expect(err).To(BeNil())
			_, err = charlie.LoadFile("charlieFile")
			Expect(err).ToNot(BeNil())
			// Charlie trying to create invitation after he has been revoked
			_, err = charlie.CreateInvitation("charlieFile", "alice")
			Expect(err).ToNot(BeNil())
			for key, _ := range dMap4 {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, []byte(""))
			}
			data, err = alice.LoadFile("file2")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(data, []byte(contentOne+contentTwo))).To(BeTrue())
		})

		Specify("Custom Test: Testing confidentiality of file 2", func() {
			userlib.DebugMsg("Custom Test: Testing confidentiality of file 2")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile("file1", []byte(contentOne))

			dMap = userlib.DatastoreGetMap()
			dMap2 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap2[key] = val
			}

			for key, _ := range dMap2 {
				if _, ok := dMap1[key]; ok {
					delete(dMap2, key)
				}
			}

			for key, _ := range dMap2 {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, ([]byte("tampered")))
			}

			_, err = alice.LoadFile("file1")
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Testing error at accepting invitation to a filename that already exists", func() {
			userlib.DebugMsg("Custom Test: Testing error at accepting invitation to a filename that already exists")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			bob.StoreFile(bobFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Testing inviting and revoking right afterwards", func() {
			userlib.DebugMsg("Custom Test: Testing inviting and revoking right afterwards")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file")

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess("randomname", "bob")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "cat")
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Chain of invites", func() {
			userlib.DebugMsg("Custom Test: Chain of invites")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file")

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			err = bob.RevokeAccess(bobFile, "alice")
			Expect(err).ToNot(BeNil())

			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			charlieInvite, err := bob.CreateInvitation(bobFile, "charlie")
			Expect(err).To(BeNil())

			err = charlie.AcceptInvitation("bob", charlieInvite, charlesFile)
			Expect(err).To(BeNil())

			err = charlie.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err := charlie.LoadFile(charlesFile)
			Expect(bytes.Equal(data, []byte(contentOne+contentThree))).To(BeTrue())

			david, err := client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())

			davidInvite, err := charlie.CreateInvitation(charlesFile, "david")
			Expect(err).To(BeNil())

			err = david.AcceptInvitation("charlie", davidInvite, "davidFile")
			Expect(err).To(BeNil())

			data, err = david.LoadFile("davidFile")
			Expect(bytes.Equal(data, []byte(contentOne+contentThree))).To(BeTrue())

			err = david.AppendToFile("davidFile", []byte(contentThree))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Compromising User data", func() {
			userlib.DebugMsg("Custom Test: Compromising User data")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			dMap := userlib.DatastoreGetMap()
			dMap1 := make(map[userlib.UUID][]byte)
			for key, val := range dMap {
				dMap1[key] = val
			}
			for key, _ := range dMap1 {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, []byte(contentTwo))
			}
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Test empty append", func() {
			userlib.DebugMsg("Custom Test: Test empty append")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file1", []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.AppendToFile("file1", []byte(""))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Test Empty File Name", func() {
			userlib.DebugMsg("Custom Test: Test Empty File Name")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())
			file1, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			fileUUID, err := alice.CreateInvitation("", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", fileUUID, "")
			Expect(err).To(BeNil())
			file2, err := bob.LoadFile("")
			Expect(err).To(BeNil())
			Expect(file1).To(Equal(file2))
		})

		Specify("Custom Test: should error if length of content is shortened.", func() {
			userlib.DebugMsg("Custom Test: should error if length of content is shortened.")
			blank_slate := userlib.DatastoreGetMap()
			client.InitUser("alice", defaultPassword)
			new_slate := userlib.DatastoreGetMap()
			for key := range blank_slate {
				delete(new_slate, key)
			}
			for key := range new_slate {
				userlib.DatastoreSet(key, []byte(""))
			}
			_, err := client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Test Overwrite", func() {
			userlib.DebugMsg("Custom Test: Test Overwrite")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file1", []byte(contentOne))
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			file1, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(file1, []byte(contentOne))).To(BeTrue())
			bobInv, err := alice.CreateInvitation("file1", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", bobInv, "bobFile")
			data, err := bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(data, []byte(contentOne))).To(BeTrue())

			err = alice.StoreFile("file1", []byte(contentTwo))
			Expect(err).To(BeNil())
			file2, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(file2, []byte(contentTwo))).To(BeTrue())
			data2, err := bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(data2, []byte(contentTwo))).To(BeTrue())

			err = bob.StoreFile("bobFile", []byte(contentThree))
			Expect(err).To(BeNil())
			file3, err := alice.LoadFile("file1")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(file3, []byte(contentThree))).To(BeTrue())
			data3, err := bob.LoadFile("bobFile")
			Expect(err).To(BeNil())
			Expect(bytes.Equal(data3, []byte(contentThree))).To(BeTrue())

		})

		Specify("Custom Test: Accepting someone else's invitation", func() {
			userlib.DebugMsg("Custom Test: Accepting someone else's invitation")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			bobInv, err := alice.CreateInvitation(aliceFile, "bob")
			_, ok := userlib.DatastoreGet(bobInv)
			Expect(ok).To(BeTrue())
			Expect(err).To(BeNil())
			err = charlie.AcceptInvitation("alice", bobInv, "charliefile")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Messy sequence of events", func() {
			userlib.DebugMsg("Custom Test: Messy sequence of events")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.LoadFile("file1")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			bobInv, err := alice.CreateInvitation(aliceFile, "bob")
			_, ok := userlib.DatastoreGet(bobInv)
			Expect(ok).To(BeTrue())
			Expect(err).To(BeNil())
			err = charlie.AcceptInvitation("alice", bobInv, "charliefile")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Adding more revocation edge case", func() {
			userlib.DebugMsg("Custom Test: Revoking yourself")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file", []byte(contentTwo))
			Expect(err).To(BeNil())
			err = alice.RevokeAccess("file", "alice")
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile("file")
			Expect(err).To(BeNil())
			err = alice.AppendToFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Creating invitation to yourself", func() {
			userlib.DebugMsg("Custom Test: Creating invitation to yourself")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file", []byte(contentTwo))
			Expect(err).To(BeNil())
			badInv, err := alice.CreateInvitation("file", "alice")
			Expect(err).ToNot(BeNil())
			err = alice.AcceptInvitation("alice", badInv, "file")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Append Functionality", func() {
			userlib.DebugMsg("Custom Test: Append Functionality")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file", []byte(contentOne+contentTwo))
			Expect(err).To(BeNil())
			err = bob.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
			err = bob.AppendToFile("file", []byte(contentTwo))
			Expect(err).To(BeNil())
			aContent, err := alice.LoadFile("file")
			Expect(err).To(BeNil())
			bContent, err := bob.LoadFile("file")
			Expect(err).To(BeNil())
			Expect(aContent).To(Equal(bContent))
		})

		Specify("Custom Test: File name length leakage", func() {
			userlib.DebugMsg("Custom Test: File name length leakage")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())
			map1 := userlib.DatastoreGetMap()

			map1Max := 0
			for _, v := range map1 {
				x := len(v)
				if x > map1Max {
					map1Max = x
				}
			}

			userlib.DatastoreClear()
			userlib.KeystoreClear()

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile(string(bytes.Repeat([]byte(contentOne), 100)), []byte(contentOne))
			Expect(err).To(BeNil())
			map2 := userlib.DatastoreGetMap()

			map2Max := 0
			for _, v := range map2 {
				x := len(v)
				if x > map2Max {
					map2Max = x
				}
			}

			diff := map1Max - map2Max
			if diff < 0 {
				diff *= -1
			}

			Expect(diff < 15).To(BeTrue())

		})

		Specify("Custom Test: Invitation to nonexistent user", func() {
			userlib.DebugMsg("Custom Test: Invitation to nonexistent user")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = bob.StoreFile("file", []byte(contentOne))
			Expect(err).To(BeNil())

			_, err = bob.CreateInvitation("file", "nonexistentuser")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: appendfile on nonexistent file", func() {
			userlib.DebugMsg("Custom Test: appendfile on nonexistent file")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			err = bob.AppendToFile("idontexist", []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: loadfile on nonexistent file", func() {
			userlib.DebugMsg("Custom Test: appendfile on nonexistent file")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			_, err = bob.LoadFile("idontexist")
			Expect(err).ToNot(BeNil())
		})

	})

})
