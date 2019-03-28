package main

import (
	"encoding/base64"
	"fmt"

	phe "github.com/VirgilSecurity/virgil-phe-go"
	purekit "github.com/VirgilSecurity/virgil-purekit-go"
)

func InitPureKit() (*purekit.Protocol, error) {
	// Set here your PureKit credentials
	appToken := "AT.GxqQu6z8kwIO3HuBYAJN1Wdv9YL5yBGl"
	appSecretKey := "SK.1.w3IY3Q/7QMUow/poZFs9KpQ5ElsFUjYEbsjoFso2Oec="
	servicePublicKey := "PK.1.BBtpQGyPxJRXvA5mpc8HCHUMm9a+Zi88ZuOtU/LWhP+dLH+sSKbnHrTubj7+0+KZyaeeuTP34OfGBlCXLIIJT4I="
	updateToken := "" // leave empty if not rotating keys
	context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, updateToken)
	if err != nil {
		return nil, err
	}

	return purekit.NewProtocol(context)
}

// For the purpose of this guide, we'll use a simple struct and an array
// to simulate a database. As you go, remove/replace with your actual database logic.
type User struct {
	username string

	// If you have any password field for authentication, it can and should
	// be deprecated after enrolling the user with PureKit
	passwordHash string

	// Data to be protected
	ssn string

	// Field needed for PureKit
	record string
}

var UserTable []User

// Create a new encrypted password record using user password or its hash
func EnrollAccount(userId int, password string, protocol *purekit.Protocol) error {
	user := &UserTable[userId]

	record, key, err := protocol.EnrollAccount(password)
	if err != nil {
		return err
	}

	// Save record to database
	UserTable[userId].record = base64.StdEncoding.EncodeToString(record)

	// Deprecate existing user password field & save in database
	user.passwordHash = ""

	// Use encryptionKey for protecting user data & save in database
	encryptedSsn, err := phe.Encrypt([]byte(user.ssn), key)
	user.ssn = base64.StdEncoding.EncodeToString(encryptedSsn)

	return nil
}

// Verifies password and returns encryption key for a user
func VerifyPassword(userId int, password string, protocol *purekit.Protocol) ([]byte, error) {
	recordString, err := base64.StdEncoding.DecodeString(UserTable[userId].record)
	record := []byte(recordString)

	key, err := protocol.VerifyPassword(password, record)
	if err != nil {
		if err == purekit.ErrInvalidPassword {
			// Invalid password
		}

		return key, err // Some other error
	}

	return key, err
}

func main() {
	protocol, err := InitPureKit()

	if err != nil {
		panic(err)
	}

	// Adding test users for the purpose of this guide.
	UserTable = append(UserTable, User{username: "alice123", passwordHash: "80815C001", ssn: "036-24-9546"})
	UserTable = append(UserTable, User{username: "bob321", passwordHash: "411C315N1C3", ssn: "041-53-8723"})

	// Enroll all your user accounts
	for k, _ := range UserTable {
		fmt.Printf("Enrolling user '%s': ", UserTable[k].username)

		// Ideally, you'll ask for users to create a new password, but
		// for this guide, we'll use existing password in DB
		EnrollAccount(k, UserTable[k].passwordHash, protocol)
		fmt.Printf("%+v\n\n", UserTable[k])
	}

	// Verify password of a user
	userId := 0
	user := UserTable[userId]

	key, err := VerifyPassword(userId, "80815C001", protocol)

	// Use key for decrypting user data
	decodedSsn, err := base64.StdEncoding.DecodeString(user.ssn)
	decryptedSsn, err := phe.Decrypt([]byte(decodedSsn), key)

	fmt.Printf("'%s's SSN: %s\n", user.username, decryptedSsn)

	homeAddress := []byte("1600 Pennsylvania Ave NW, Washington, DC 20500, EUA")
	encryptedAddress, err := phe.Encrypt(homeAddress, key)
	encryptedAddressB64 := base64.StdEncoding.EncodeToString(encryptedAddress)

	if err != nil {
		panic(err)
	}

	// Decrypt user data

	decryptedAddress, err := phe.Decrypt(encryptedAddress, key)

	if err != nil {
		panic(err)
	}

	fmt.Printf("'%s's encrypted home address: %s\n", UserTable[0].username, encryptedAddressB64)
	fmt.Printf("'%s's home address: %s\n", UserTable[0].username, string(decryptedAddress))
}
