# Passw0rd SDK Go

[![Build Status](https://travis-ci.com/passw0rd/sdk-go.png?branch=master)](https://travis-ci.com/passw0rd/sdk-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Passw0rd Features](#passw0rd-features) | [Register your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Setup your Database](#setup-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces to developers an implementation of the [Password-Hardened Encryption (PHE) protocol](https://www.chaac.tf.fau.de/files/2018/06/main.pdf) that provides developers with a technology to protect users passwords from offline/online attacks and make stolen passwords useless even if your database has been compromised.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user's password.


## Passw0rd Features
- zero knowledge of user's password
- protection from online attacks
- protection from offline attacks
- instant invalidation of stolen database
- user data encryption with a personal key


## Register your Account
Before starting practicing with the SDK and usage examples be sure that:
- you have a registered Account at Virgil Cloud
- you have a registered Passw0rd Application
- and you got your Passw0rd Application's credentials, such as: Application ID, Access Token, Service Public Key, Client Secret Key.

If you don't have an account or a passw0rd project with its credentials, please use the [Passw0rd CLI](https://github.com/passw0rd/cli) to get it.


## Install and configure SDK
The Passw0rd Go SDK is provided as a package named `passw0rd`. The package is distributed via GitHub. The package is available for Go 1.10 or newer.


### Install SDK Package

Install Passw0rd SDK library with the following code:
```bash
go get -u github.com/passw0rd/sdk-go
```


### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```go
// here set your Virgil Account and Passw0rd credentials
import (
    "github.com/passw0rd/sdk-go"
)

func InitPassw0rd() (*passw0rd.Protocol, error){
    accessToken := "OSoPhirdopvijQl-FPKdlSydN9BUrn5oEuDwf3-Hqps="
    privStr := "SK.1.xacDjofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    pubStr := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="
    appId := "c7717707d03f4d3589804e7509e5d7d7"

    context, err := passw0rd.CreateContext(accessToken, appId, privStr, pubStr)
    if err != nil{
        return nil, err
    }

    return passw0rd.NewProtocol(context)
}
```



## Setup your Database
Passw0rd SDK allows you to easily perform all the necessary operations to create, verify and update user's password without requiring any additional actions.

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

### Enroll user's passw0rd

Use this flow to create a new passw0rd record for a user in your DB.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in to your system to implement Passw0rd. You can go through your database and enroll user's passw0rd at any time.

So, in order to create passw0rd for a new database or an available one, go through the following operations:
- Take user's **password** (or its hash or whatever you use) and pass it into the `EnrollAsync` function in SDK on your Server side.
- Passw0rd SDK will send a request to Passw0rd Service to get enrollment.
- Then, Passw0rd SDK will create user's Passw0rd **record**. You need to store this unique user's `record` (recordBytes or recordBase64 format) in your database in an associated column.

```go
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/passw0rd/sdk-go"
)

// create a new encrypted password record using user's password or its hash
func EnrollAccount(password string) error{
    ctx, err := passw0rd.CreateContext("ACCESS_TOKEN", "APP_ID", "CLIENT_SECRET_KEY", "SERVER_PUBLIC_KEY")
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


### Verify user's passw0rd

Use this flow at the "sign in" step when a user already has his or her own unique `record` in your database. This function allows you to verify that the password that the user has passed is correct. 
You have to pass his or her `record` from your DB into the `VerifyPassword` function:

```go
package main

import (
    "fmt"
    "github.com/passw0rd/sdk-go"
)


func VerifyPassword(password string, record []byte) error{
    ctx, err := passw0rd.CreateContext("ACCESS_TOKEN", "APP_ID", "CLIENT_SECRET_KEY", "SERVER_PUBLIC_KEY")
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


### Update user's passw0rd

This function allows you to use a special `UpdateTokens` to update users' `record` in your database.

> Use this flow only if your database has been COMPROMISED!
When a user just needs to change his or her own password, use the `enroll` function to replace old user's `passw0rd_record` value in your DB with a new user's `passw0rd_record`.

How it works:
- Get your `UpdateToken` using [Passw0rd CLI](https://github.com/passw0rd/cli).
- Specify the `UpdateToken` in the Passw0rd SDK on your Server side.
- Then use the `Update` records function to create new user's `record` for your users (you don't need to ask your users to create a new password).
- Finally, save the new user's `record` into your database.

Here is an example of using the `Update` records function:
```go
package main

import (
    "github.com/passw0rd/sdk-go"
)


func UpdatePassword(oldRecord []byte) (newRecord[]byte, err error){
    ctx, err := passw0rd.CreateContext("ACCESS_TOKEN", "APP_ID", "CLIENT_SECRET_KEY", "SERVER_PUBLIC_KEY", "UPDATE_TOKEN")
    if err != nil {
        return
    }

    prot, err := passw0rd.NewProtocol(ctx)
    if err != nil {
        return
    }

    //return updated record
    newRecord, err = prot.UpdateEnrollmentRecord(oldRecord)
    if err != nil {
        return
    }

    return

}
```


## Docs
* [Passw0rd][_passw0rd] home page
* [The PHE WhitePaper](https://www.chaac.tf.fau.de/files/2018/06/main.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

Also, get extra help from our support team: support@VirgilSecurity.com.

[_passw0rd]: https://passw0rd.io/
