
# Virgil PureKit Go

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-go.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

<a href="https://developer.virgilsecurity.com"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/purekit/PureKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and lessens the security risks associated with weak passwords.

Virgil PureKit allows developers interacts with Virgil PHE Service to protect users' passwords and sensitive personal identifiable information (PII data) in a database from offline/online attacks and makes stolen passwords/data useless if your database has been compromised. Neither Virgil nor attackers know anything about users' passwords/data.

This technology can be used within any database or login system that uses a password, so it’s accessible for a company of any industry or size.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of users' passwords
- Passwords & data protection from online attacks
- Passwords & data protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key

## Get Started with PureKit

This guide is the first step to adding password-hardened encryption to your database. Here you can learn how to set up PureKit at your backend to protect your users's passwords and data.

For more details about password-hardened encryption (PHE), take a look at our overview [here](/docs/purekit/fundamentals/password-hardened-encryption/).

## Install and configure PureKit

### Install PureKit package

Use your package manager to download PureKit into your backend.



Install PureKit Golang SDK library with the following code:

```bash
go get -u github.com/VirgilSecurity/virgil-purekit-go
```

SDK uses Dep to do manage its dependencies.
More about the Dep: "https://golang.github.io/dep/docs/installation.html"

Please install Dep and run the following commands:

```bash
cd $(go env GOPATH)/src/github.com/VirgilSecurity/virgil-purekit-go
dep ensure
```


### Configure PureKit
Navigate to [Virgil Dashboard](https://dashboard.virgilsecurity.com), create a new Pure application and configure PureKit framework with your application credentials:

```bash

package main

import (
    "encoding/base64"
    "fmt"
    "github.com/VirgilSecurity/virgil-purekit-go"
    "github.com/VirgilSecurity/virgil-phe-go"
)

func InitPureKit() (purekit.Protocol, error){
    // Set here your PureKit credentials
    appToken := "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.xacDjofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="

    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}

func main() {
    protocol, err := InitPureKit()

    if err != nil {
        panic(err)
    }

    // 'protocol' will be used in the next step
    // Next step: Enroll user accounts
}
```


#### Prepare your database

A **Pure record** is a user password that is protected with our PureKit technology. A Pure Record contains the version, client & server random salts, and two values obtained during the execution of the PHE protocol.

In order to create and work with a user's `record`, you need to add an additional column to your database table.

The column must have the following parameters:

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|record|bytearray|210|A unique Pure record, namely a user's protected password.|

#### Generate a recovery key pair (optional)

To be able to move away from Pure without having to put your users through registering again, or just to be able to recover data that your users may lose, you need to make a backup of your database, generate a recovery key pair and encrypt your backup with the recovery public key. The public key will be used to encrypt the database at the enrollment step.

To generate a recovery keypair, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

<Warning>

You won’t be able to restore your recovery private key, so it is crucial not to lose it.

</Warning>

```bash

package main

import (
    "encoding/base64"

    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

func main() {
    crypto := virgil_crypto_go.NewVirgilCrypto()
    kp, err := crypto.GenerateKeypair()
    if err != nil {
        panic(err)
    }
    pk, err := crypto.ExportPublicKey(kp.PublicKey())
    if err != nil {
        panic(err)
    }
    sk, err := crypto.ExportPrivateKey(kp.PrivateKey(), "")
    if err != nil {
        panic(err)
    }
    recoveryPrivateKey := base64.StdEncoding.EncodeToString(pk)
    recoveryPublicKey := base64.StdEncoding.EncodeToString(sk)
}
```
## Usage Examples

### Generate user's Pure Record

To create a Pure `record` for a database:
- Take the user's **password** (or hash) and pass it into the `EnrollAccount` function.
- Store this user's unique `record` in your database.

The enrollment snippet below also provides an example on how to [protect user personal data](/docs/purekit/data-encryption/) with `encryptionKey` and encrypt user password hashes with `recoveryPublicKey`.

<Warning>

Keep in mind that this step will replace password hashes with Pure Records, so it's important to go through all steps in [Prerequisites](#prerequisites).

If you need to update your user's Pure Records, for instance, if your database is COMPROMISED, take the immediate steps according to [this guide](/docs/purekit/additional-guides/rotate-keys-records/).

</Warning>

```bash

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

    // Encrypted hash backup
    encryptedPasswordHash []byte
}

var UserTable []User

// Create a new encrypted password record using user password or its hash
func EnrollAccount(userId int, password string, protocol *purekit.Protocol, crypto *virgil_crypto_go.ExternalCrypto, recoveryKey cryptoapi.PublicKey) error {
    user := &UserTable[userId]

    record, key, err := protocol.EnrollAccount(password)
    if err != nil {
        return err
    }

    // Save the user's record to database
    UserTable[userId].record = base64.StdEncoding.EncodeToString(record)

    user.passwordHash = ""
    // Use Recovery Public Key to encrypt user's password hash
    user.encryptedPasswordHash, err = crypto.Encrypt([]byte(user.passwordHash), recoveryKey)
    if err != nil {
        return err
    }

    // Use EncryptionKey for protecting user data
    // Save the result in a database
    encryptedSsn, err := phe.Encrypt([]byte(user.ssn), key)
    user.ssn = base64.StdEncoding.EncodeToString(encryptedSsn)

    return nil
}

func main() {
    // Previous step: initialize purekit

    crypto := virgil_crypto_go.NewVirgilCrypto()
    // Adding test users for the purpose of this guide.
    UserTable = append(UserTable, User{username: "alice123", passwordHash: "80815C001", ssn: "036-24-9546"})
    UserTable = append(UserTable, User{username: "bob321", passwordHash: "411C315N1C3", ssn: "041-53-8723"})

    recoveryKey, err := crypto.ImportPublicKey([]byte(recoveryPublicKey))
    if err != nil {
        panic(err)
    }
    // Enroll all your user accounts
    for k, _ := range UserTable {
        fmt.Printf("Enrolling user '%s': ", UserTable[k].username)

        // Ideally, you'll ask for users to create a new password, but
        // for this guide, we'll use existing password in DB
        EnrollAccount(k, UserTable[k].passwordHash, protocol, crypto, recoveryKey)
        fmt.Printf("%+v\n\n", UserTable[k])
    }
}
```

**Note!** If you have a database with user passwords, you don't have to wait until they log in. You can go through your database and enroll (create) a user's Pure Record at any time.

### Verify user's password

After a user has their Pure Record, you can authenticate the user by verifying their password using the `VerifyPassword` function:

```bash

// Verifies password and returns encryption key for a user
func VerifyPassword(userId int, password string, protocol purekit.Protocol) ([]byte, error) {
    recordString, err := base64.StdEncoding.DecodeString(UserTable[userId].record)
    record := []byte(recordString)

    key, err := protocol.VerifyPassword(password, record)
    if err != nil {
        if err == purekit.ErrInvalidPassword{
            // Invalid password
        }

        return key, err // Some other error
    }

    return key, err
}

func main() {
    // Previous step: enroll accounts

    // Verify password of a user
    userId := 0
    user := UserTable[userId]

    key, err := VerifyPassword(userId, "80815C001", protocol)

    // Use key for decrypting user data
    decodedSsn, err := base64.StdEncoding.DecodeString(user.ssn)
    decryptedSsn, err := phe.Decrypt([]byte(decodedSsn), key)

    fmt.Printf("'%s's SSN: %s\n", user.username, decryptedSsn)
}
```

### Change user's password

Use this flow when a user wants to change their password.

<Warning>

If you use PureKit not only for hardening passwords, but also for encrypting user's data, you'll have to re-encrypt user's data with the new key so that the user doesn't lose access to it. Navigate to [this guide](/docs/purekit/data-encryption/#re-encrypt-data-when-password-is-changed) and follow the instructions there.

</Warning>

If you're using PureKit only for encrypting passwords, then you have to simply create a new Pure Record using the new password for the user, and replace the old Pure Record with the new one.



### Data encryption & decryption

The PHE service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from the `enrollAccount` or `verifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) a user's Pure Record. The `encryptionKey` will be updated after a user changes their own password.

> Virgil Security has zero knowledge about a user's `encryptionKey`, because the key is calculated every time you execute the `enrollAccount` or `verifyPassword` functions on your server side.

> Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and the random 256-bit salt.

Here is an example of data encryption/decryption with an `encryptionKey`:

```bash

func main() {
    // Previous step: verify password

    // Use key for encrypting user data
    homeAddress := []byte("1600 Pennsylvania Ave NW, Washington, DC 20500, EUA")
    encryptedAddress, err := phe.Encrypt(homeAddress, key)
    encryptedAddressB64 := base64.StdEncoding.EncodeToString(encryptedAddress)

    if err != nil {
        panic(err)
    }

    // Use key for decrypting user data

    decryptedAddress, err := phe.Decrypt(encryptedAddress, key)

    if err != nil {
        panic(err)
    }

    fmt.Printf("'%s's encrypted home address: %s\n", UserTable[0].username, encryptedAddressB64)
    fmt.Printf("'%s's home address: %s\n", UserTable[0].username, string(decryptedAddress))
}
```

### Re-encrypt data when password is changed

Use this flow when a user wants to change their password and maintain access to their data.

When Pure Record for the user is created for the very first time, generate a new key (let's call it `User Key`) and store it in your database.

#### Prepare database

Create a new column in your database for storing `User Keys`.

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|Ecnrypted User Key|bytearray|210|A unique key for user's data encryption.|

#### Obtain Pure Record key

When the Pure Record is created for the very first time, you need to obtain the `encryptionKey` from the `enrollAccount` function (see the [Generate User's Pure Record](/docs/purekit/password-encryption/#generate-users-pure-record) section).

#### Generate User Key

To generate a `User Key`, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.


#### Encrypt and store User Key

Encrypt the `User Key` with the `encryptionKey` and save the `Encrypted User Key` at your database.

#### Encrypt data with User Key

Whenever the user needs to encrypt their data, decrypt the `Encrypted User Key` with the `encryptionKey` and use the decrypted `User Key` instead of the `encryptionKey` for encrypting user's data.

#### Change user's password

To change the password, user enters their old password to authenticate at backend, and the new password. Use their new password to create a new Pure Record for the user.

During the password change, decrypt the `Encrypted User Key` with the old `encryptionKey` and encrypt the `User Key` with the new `encryptionKey` you get from `enrollAccount` using the new password. This will allow the user to access their data without re-encrypting all of it.

After that, you can delete the old Pure Record from your database and save the new one instead.

### Rotate Keys and Records

This guide shows how to rotate PureKit-related keys and update Pure Records. There can never be enough security, so you should rotate your sensitive data regularly (about once a week).

**Also, use this flow in case your database has been COMPROMISED!**

Use this workflow to get an `update_token` for updating user's Pure Record in your database and to get a new `app_secret_key` and `service_public_key` for your application.

**Note!** When a user just needs to change their password, use the `EnrollAccount` function (see the [Password Encryption](#password-encryption) step) to replace the user's old `record` value in your DB with a new `record`.

Learn more about Pure Records and keys rotation as a part of Post-Compromise Security in [this guide](/docs/purekit/fundamentals/post-compromise-security/).

#### Get your update token

Navigate to your Application panel at Virgil Dashboard and, after pressing "BEGIN ROTATION PROCESS" press “SHOW UPDATE TOKEN” button to get the `update_token`.

#### Initialize PureKit with the update token

Move to PureKit configuration file and specify your `update_token`:

```bash

func InitPureKit() (purekit.Protocol, error){
    appToken := "AT.0000000irdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.000jofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6Vdf00000QQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="
    updateToken := "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000="

    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, updateToken)
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}
```

#### Start migration

- Run the `update` method of the `RecordUpdater` class to create a new user `record`
- Save user's new `record` into your database.

```bash
func main(){
    // Previous step: initialize PureKit SDK with Update Token

    // Initialize Record Updater
    updater, err := purekit.NewRecordUpdater("Update Token")

    if err != nil {
        panic(err)
    }

    // Update user records & save to database
    for k, _ := range UserTable {
        recordString, err := base64.StdEncoding.DecodeString(UserTable[k].record)

        if err != nil {
            panic(err)
        }

        record := []byte(recordString)
        newRecord, err := updater.UpdateRecord(record)
        UserTable[k].record = base64.StdEncoding.EncodeToString(newRecord)
    }
}
```

> **Note!** You don't need to ask your users for a new password.

> **Note!** The SDK is able to work with two versions of a user's `record` (old and new). This means, if a user logs into your system when you do the migration, the PureKit SDK will verify their password without any problems.


#### Download CLI

After you updated your database records, it's required to update (rotate) your application credentials. For security reasons, you need to use the [Virgil CLI utility](https://github.com/VirgilSecurity/virgil-cli).

**Download** the preferred CLI package with one of the links below:
- [Mac OS](https://github.com/VirgilSecurity/virgil-cli/releases)
- [FreeBSD](https://github.com/VirgilSecurity/virgil-cli/releases)
- [Linux OS](https://github.com/VirgilSecurity/virgil-cli/releases)
- [Windows OS](https://github.com/VirgilSecurity/virgil-cli/releases)


#### Rotate app secret key

Use Virgil CLI `update-keys` command and your `update_token` to update the `app_secret_key` and `service_public_key`:

```bash
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

#### Configure PureKit SDK with new credentials

Move to PureKit SDK configuration and replace your previous `app_secret_key`, `service_public_key` with a new one (same for the `app_token`). Delete `update_token` and previous `app_secret_key`, `service_public_key`.

```bash

// here set your purekit credentials
import (
    "github.com/VirgilSecurity/virgil-purekit-go"
)

func InitPureKit() (purekit.Protocol, error){
    appToken := "App Token"
    appSecretKey := "New App Secret Key"
    servicePublicKey := "New Service Public Key"

    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}
```

### Uninstall PureKit

Use this workflow to move away from Pure without having to put your users through registering again. This can be carried out by decrypting the encrypted database backup (users password hashes included) and replacing the encrypted data with it.

#### Prepare your recovery key

In order to recover the original password hashes, you need to prepare your recovery private key.

> If you don't have a recovery key, then you have to ask your users to go through the registration process again to restore their passwords.


#### Decrypt encrypted password hashes

Now use your recovery private key to get original password hashes:

```bash

crypto := virgil_crypto_go.NewVirgilCrypto()

privateKey, err := crypto.ImportPrivateKey([]byte(recoveryPrivateKey), "")
if err != nil{
    return err
}
decryptedPasswordHash, err := crypto.Decrypt(encryptedPasswordHash, privateKey)
```

Save the decrypted users password hashes into your database.
After the recovery process is done, you can delete all the Pure data and the recovery keypair.


## Docs
* [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol
* [Go Samples](/samples) - explore our Go PURE samples to easily run the SDK
* [PURE use-case](https://developer.virgilsecurity.com/docs/use-cases/v1/passwords-and-data-protection) - explore our use-case to protect user passwords and data in your database from data breaches

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
