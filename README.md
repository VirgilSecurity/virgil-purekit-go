# Passw0rd SDK Go

[![Build Status](https://travis-ci.com/passw0rd/sdk-go.png?branch=master)](https://travis-ci.com/passw0rd/sdk-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers with a technology to protect users passwords from offline/online attacks and make stolen passwords useless even if your database has been compromised.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user's password.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of user password
- Protection from online attacks
- Protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key


## Register Your Account
Before starting practicing with the SDK and usage examples be sure that:
- you have a registered passw0rd Account
- you created passw0rd Application
- and you got your passw0rd application's credentials, such as: Application Access Token, Service Public Key, Client Secret Key

If you don't have an account or a passw0rd project with its credentials, please use the [passw0rd CLI](https://github.com/passw0rd/cli) to get it.


## Install and Configure SDK
The passw0rd Go SDK is provided as a package named `passw0rd`. The package is distributed via GitHub. The package is available for Go 1.10 or newer.


### Install SDK Package
Install passw0rd SDK library with the following code:
```bash
go get -u github.com/passw0rd/sdk-go
```
Passw0rd Go SDK uses Dep to do manage its dependencies:
Please install [dep](https://golang.github.io/dep/docs/installation.html) and run the following commands:
```bash
cd $(go env GOPATH)/src/github.com/passw0rd/sdk-go
dep ensure
```


### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```go
// here set your passw0rd credentials
import (
    "github.com/passw0rd/sdk-go"
)

func InitPassw0rd() (*passw0rd.Protocol, error){
    appToken := "PT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.xacDjofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="

    context, err := passw0rd.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return passw0rd.NewProtocol(context)
}
```



## Prepare Your Database
Passw0rd SDK allows you to easily perform all the necessary operations to create, verify and rotate user password without requiring any additional actions.

In order to create and work with user's protected passw0rd you have to set up your database with an additional column.

The column must have the following parameters:
<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>passw0rd_record</td>
	<td>bytearray</td>
	<td>210</td>
	<td> A unique record, namely a user's protected passw0rd.</td>
</tr>

</tbody>
</table>


## Usage Examples

### Enroll User passw0rd

Use this flow to create a new passw0rd record for a user in your DB.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in to your system to implement Passw0rd. You can go through your database and enroll user passw0rd at any time.

So, in order to create passw0rd for a new database or an available one, go through the following operations:
- Take user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccount` function in SDK on your Server side.
- Passw0rd SDK will send a request to passw0rd service to get enrollment.
- Then, passw0rd SDK will create user's passw0rd **record**. You need to store this unique user's `record` (recordBytes or recordBase64 format) in your database in an associated column.

```go
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/passw0rd/sdk-go"
)

// create a new encrypted password record using user password or its hash
func EnrollAccount(password string) error{
    ctx, err := passw0rd.CreateContext("APP_TOKEN", "SERVICE_PUBLIC_KEY", "CLIENT_SECRET_KEY", "[OPTIONAL_UPDATE_TOKEN]")
    if err != nil {
        return err
    }

    prot, err := passw0rd.NewProtocol(ctx)
    if err != nil {
        return err
    }

    record, key, err := prot.EnrollAccount(password)
    if err != nil {
        return err
    }

    //save record to database
    fmt.Printf("Database record: %s\n", base64.StdEncoding.EncodeToString(record))
    //use encryption key for protecting user data
    fmt.Printf("Encryption key: %x\n", key)

    return nil

}
```

When you've created a `passw0rd_record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User passw0rd

Use this flow at the "sign in" step when a user already has his or her own unique `record` in your database. This function allows you to verify that the password that the user has passed is correct.
You have to pass his or her `record` from your DB into the `VerifyPassword` function:

```go
package main

import (
    "fmt"
    "github.com/passw0rd/sdk-go"
)


func VerifyPassword(password string, record []byte) error{
    ctx, err := passw0rd.CreateContext("APP_TOKEN", "SERVICE_PUBLIC_KEY", "CLIENT_SECRET_KEY", "[OPTIONAL_UPDATE_TOKEN]")
    if err != nil {
        return err
    }

    prot, err := passw0rd.NewProtocol(ctx)
    if err != nil {
        return err
    }

    key, err := prot.VerifyPassword(password, record)
    if err != nil {

        if err == passw0rd.ErrInvalidPassword{
            //invalid password
        }
        return err //some other error
    }

    //use encryption key for decrypting user data
    fmt.Printf("Encryption key: %x\n", key)

    return nil

}
```


## Rotate app keys and user record
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this flow to get an `UPDATE_TOKEN` for updating user's passw0rd `RECORD` in your database and to get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to do any modification with available one. When a user just needs to change his or her own password, use the EnrollAccount function to replace user's old passw0rd record value in your DB with a new record.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN` using [Passw0rd CLI](https://github.com/passw0rd/cli)

- be sure you're logged in your account. To log in the account use the following command (2FA is required):

```bash
// FreeBSD / Linux / Mac OS
./passw0rd login my@email.com

// Windows OS
passw0rd login my@email.com
```

- then, use the `rotate` command and your application token to get an `UPDATE_TOKEN`:

```bash
// FreeBSD / Linux / Mac OS
./passw0rd application rotate <app_token>

// Windows OS
passw0rd application rotate <app_token>
```
as a result, you get your `UPDATE_TOKEN`.

**Step 2.** Initialize passw0rd SDK with the `UPDATE_TOKEN`.
Move to passw0rd SDK configuration file and specify your `UPDATE_TOKEN`:

```go
// here set your passw0rd credentials
import (
    "github.com/passw0rd/sdk-go"
)

func InitPassw0rd() (*passw0rd.Protocol, error){
    appToken := "PT.0000000irdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.000jofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6Vdf00000QQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="
    updateToken := "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000="

    context, err := passw0rd.CreateContext(appToken, servicePublicKey, appSecretKey, updateToken)
    if err != nil{
        return nil, err
    }

    return passw0rd.NewProtocol(context)
}
```

**Step 3.** Use the `UpdateEnrollmentRecord()` SDK function to create a user's `newRECORD` (you don't need to ask your users to create a new password). The `UpdateEnrollmentRecord()` function requires the `UPDATE_TOKEN` and user's `oldRECORD` from your DB:

```go
package main

import (
    "crypto/subtle"
    "github.com/passw0rd/sdk-go"
)

func main(){

    //get old record from the database
    oldRecord := ...

    //update old record
    newRecord, err := passw0rd.UpdateEnrollmentRecord(oldRecord, "UPDATE_TOKEN")
    if err != nil{
        //something went wrong
    }

    // newRecord is nil ONLY if oldRecord is already updated
    if newRecord != nil{
        //save new record to the database
        saveNewRecord(newRecord)
    }

}
```

**Step 4.** Start migration. Since the SDK is able to work simultaneously with two versions of user's records (`newRECORD` and `oldRECORD`), this will not affect the backend or users.

This means, if a user logs into your system when you do the migration, the passw0rd SDK will verify his password without any problems because Passw0rd Service already knows about both user's records (`newRECORD` and `oldRECORD`).

So, run the `UpdateEnrollmentRecord()` function and save the new user's `record` into your database.


**Step 5.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use passw0rd CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./passw0rd application update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
passw0rd application update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 6.** Move to passw0rd SDK configuration and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.

```go
// here set your passw0rd credentials
import (
    "github.com/passw0rd/sdk-go"
)

func InitPassw0rd() (*passw0rd.Protocol, error){
    appToken := "APP_TOKEN_HERE"
    appSecretKey := "NEW_APP_SECRET_KEY_HERE"
    servicePublicKey := "NEW_SERVICE_PUBLIC_KEY_HERE"


    context, err := passw0rd.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return passw0rd.NewProtocol(context)
}
```



## Docs
* [Passw0rd][_passw0rd] home page
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

Also, get extra help from our support team: support@VirgilSecurity.com.

[_passw0rd]: https://passw0rd.io/
