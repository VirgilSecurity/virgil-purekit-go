import InstallPureKitSnippet from "snippets/purekit/install"
import ConfigurePureKitSnippet from "snippets/purekit/configure"
import GenerateRecoverySnippet from "snippets/purekit/generate-recovery"

import EnrollSnippet from "snippets/purekit/enroll"
import VerifyRecordSnippet from "snippets/purekit/verify"

import PurekitEncryptDecryptSnippet from "snippets/purekit/encrypt"

import UpdateInitializeSnippet from "snippets/purekit/rotate-records/initialize"
import UpdateMigrationSnippet from "snippets/purekit/rotate-records/migrate"
import UpdateReplaceSnippet from "snippets/purekit/rotate-records/replace"

import DecryptHashes from "snippets/purekit/decrypt-hashes"


# Virgil PureKit Go SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-go.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<img src="https://cdn.virgilsecurity.com/assets/images/github/logos/pure_grey_logo.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and lessens the security risks associated with weak passwords.

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

<LanguageTabs>
<LanguageTab language="C#/.NET">


The PureKit .NET SDK is provided as a package named PureKit and distributed via NuGet package management system
The package is available for .NET Framework 4.5 and newer.

Install the PureKit .NET SDK package using Package Manager Console:

```bash
PM > Install-Package Virgil.PureKit -Version 2.0.0
```

</LanguageTab>
<LanguageTab language="GO">


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
</LanguageTab>
<LanguageTab language="KOTLIN/JAVA">


The PureKit Kotlin/Java SDK is provided as a package named purekit with group id named com.virgilsecurity.
You can either use Gradle or Maven to add it to your project dependencies.

Maven
Add `jcenter` repository:

```bash
<repositories>
    <repository>
        <id>jcenter</id>
        <name>jCenter</name>
        <url>http://jcenter.bintray.com</url>
    </repository>
</repositories>
```

and add `purekit` dependency:

```bash
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>purekit</artifactId>
        <version><latest-version></version>
    </dependency>
</dependencies>
```
Gradle

Add `jcenter` repository:

```bash
repositories {
    jcenter()
}
```
and add `purekit` dependency:
```bash
implementation "com.virgilsecurity:purekit:%latest-version%"
```
The %latest-version% of the SDK can be found in the Maven Central Repository:
https://mvnrepository.com/artifact/com.virgilsecurity/purekit

</LanguageTab>
<LanguageTab language="PHP">

The Passw0rd PHP SDK is provided as a package named virgil/purekit.
The package is distributed via Composer. The package is available for PHP 7.2 or newer.

Add the "vsce_phe_php" extension before using the SDK:

1. Download the virgil-crypto-c-{latest version} archive from the CDN: https://cdn.virgilsecurity.com/virgil-crypto-c/php/.

2. Place the "vsce_phe_php.so" file from the archive (/lib folder) into the directory with extensions

3. Add the "extension=vsce_phe_php" string in to the php.ini file

4. Restart your web-service (apache or nginx): sudo service {apache2 / nginx} restart

Tips:
PHP version: phpversion() / php --version
OS Version: PHP_OS
php.ini and extensions directory: phpinfo() / php -i / php-config --extension_dir

Also, you can launch the "extension/helper.php" file to get information about a version and extensions.

Now, install PureKit SDK library with the following code:
```bash
composer require virgil/purekit
```
</LanguageTab>
</LanguageTabs>


### Configure PureKit
Navigate to [Virgil Dashboard](https://dashboard.virgilsecurity.com), create a new Pure application and configure PureKit framework with your application credentials:

<ConfigurePureKitSnippet/>

## Prepare your database

A **Pure record** is a user password that is protected with our PureKit technology. A Pure Record contains the version, client & server random salts, and two values obtained during the execution of the PHE protocol.

In order to create and work with a user's `record`, you need to add an additional column to your database table.

The column must have the following parameters:

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|record|bytearray|210|A unique Pure record, namely a user's protected password.|

### Generate a recovery key pair (optional)

To be able to move away from Pure without having to put your users through registering again, or just to be able to recover data that your users may lose, you need to make a backup of your database, generate a recovery key pair and encrypt your backup with the recovery public key. The public key will be used to encrypt the database at the enrollment step.

To generate a recovery keypair, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

<Warning>

You won’t be able to restore your recovery private key, so it is crucial not to lose it.

</Warning>

<GenerateRecoverySnippet/>

To get the original data back using the recovery private key, go through the [recovery guide](/docs/purekit/additional-guides/uninstall/).

## Next step

Now that you have PureKit installed and configured, you are ready to move on to encrypting users' passwords:

<CardLink title="Password Encryption" href="/docs/purekit/password-encryption/" />

# Password Encryption

This guide shows how to encrypt (harden) user's password and authenticate users with Virgil PHE Service.

Learn more about how Password-Hardened Encryption works [here](/docs/purekit/fundamentals/password-hardened-encryption/).

## Prerequisites

- [PureKit installed and configured on backend](/docs/purekit/get-started/#install-purekit-package)
- [Database ready for storing Pure Records](/docs/purekit/get-started/#prepare-your-database)

## Generate user's Pure Record

To create a Pure `record` for a database:
- Take the user's **password** (or hash) and pass it into the `EnrollAccount` function.
- Store this user's unique `record` in your database.

The enrollment snippet below also provides an example on how to [protect user personal data](/docs/purekit/data-encryption/) with `encryptionKey` and encrypt user password hashes with `recoveryPublicKey`.

<Warning>

Keep in mind that this step will replace password hashes with Pure Records, so it's important to go through all steps in [Prerequisites](#prerequisites).

If you need to update your user's Pure Records, for instance, if your database is COMPROMISED, take the immediate steps according to [this guide](/docs/purekit/additional-guides/rotate-keys-records/).

</Warning>

<EnrollSnippet/>

**Note!** If you have a database with user passwords, you don't have to wait until they log in. You can go through your database and enroll (create) a user's Pure Record at any time.

## Verify user's password

After a user has their Pure Record, you can authenticate the user by verifying their password using the `VerifyPassword` function:


<VerifyRecordSnippet/>

## Change user's password

Use this flow when a user wants to change their password.

<Warning>

If you use PureKit not only for hardening passwords, but also for encrypting user's data, you'll have to re-encrypt user's data with the new key so that the user doesn't lose access to it. Navigate to [this guide](/docs/purekit/data-encryption/#re-encrypt-data-when-password-is-changed) and follow the instructions there.

</Warning>

If you're using PureKit only for encrypting passwords, then you have to [simply create a new Pure Record](/docs/purekit/password-encryption/#register-users-pure-record) using the new password for the user, and replace the old Pure Record with the new one.


## Next step

Start encrypting user's data with PureKit:

<CardLink title="Encrypt & Decrypt Data" href="/docs/purekit/data-encryption/" />

# Data Encryption

This guide shows how to encrypt and decrypt data with PureKit.

Not only user passwords are sensitive data. In this flow we will help you protect any **Personally identifiable information** (PII) in your database.

PII is data that could potentially identify a specific individual, and PII is sensitive. Sensitive PII is information, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI), and unique identifiers such as passport or Social Security numbers.

## How encryption works with PHE

The PHE service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from the `enrollAccount` or `verifyPassword` functions (see the [Verify User's Password](/docs/purekit/password-encryption/#verify-users-password) section). The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) a user's Pure Record. The `encryptionKey` will be updated after a user changes their own password.

<Info>

Virgil Security has zero knowledge about a user's `encryptionKey`, because the key is calculated every time you execute the `enrollAccount` or `verifyPassword` functions on your server side.

</Info>

<Info>

Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and the random 256-bit salt.

</Info>

## Prerequisites

- [Pure Record generation](/docs/purekit/password-encryption/)

## Data encryption & decryption

Here is an example of data encryption/decryption with an `encryptionKey`:

<PurekitEncryptDecryptSnippet/>

## Re-encrypt data when password is changed

Use this flow when a user wants to change their password and maintain access to their data.

When Pure Record for the user is created for the very first time, generate a new key (let's call it `User Key`) and store it in your database.

### Prepare database

Create a new column in your database for storing `User Keys`.

|Parameters|Type|Size (bytes)|Description|
|--- |--- |--- |--- |
|Ecnrypted User Key|bytearray|210|A unique key for user's data encryption.|

### Obtain Pure Record key

When the Pure Record is created for the very first time, you need to obtain the `encryptionKey` from the `enrollAccount` function (see the [Generate User's Pure Record](/docs/purekit/password-encryption/#generate-users-pure-record) section).

### Generate User Key

To generate a `User Key`, [install Virgil Crypto Library](https://github.com/VirgilSecurity/virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

<GenerateKeySnippet/>

### Encrypt and store User Key

Encrypt the `User Key` with the `encryptionKey` and save the `Encrypted User Key` at your database.

### Encrypt data with User Key

Whenever the user needs to encrypt their data, decrypt the `Encrypted User Key` with the `encryptionKey` and use the decrypted `User Key` instead of the `encryptionKey` for encrypting user's data.

### Change user's password

To change the password, user enters their old password to authenticate at backend, and the new password. Use their new password to [create a new Pure Record](/docs/purekit/password-encryption/#generate-users-pure-record) for the user.

During the password change, decrypt the `Encrypted User Key` with the old `encryptionKey` and encrypt the `User Key` with the new `encryptionKey` you get from `enrollAccount` using the new password. This will allow the user to access their data without re-encrypting all of it.

After that, you can delete the old Pure Record from your database and save the new one instead.

# Rotate Keys and Records

This guide shows how to rotate PureKit-related keys and update Pure Records. There can never be enough security, so you should rotate your sensitive data regularly (about once a week).

**Also, use this flow in case your database has been COMPROMISED!**

Use this workflow to get an `update_token` for updating user's Pure Record in your database and to get a new `app_secret_key` and `service_public_key` for your application.

**Note!** When a user just needs to change their password, use the `EnrollAccount` function (see the [Password Encryption](/docs/purekit/password-encryption/) step) to replace the user's old `record` value in your DB with a new `record`.

Learn more about Pure Records and keys rotation as a part of Post-Compromise Security in [this guide](/docs/purekit/fundamentals/post-compromise-security/).

## Get your update token

Navigate to your Application panel at Virgil Dashboard and, after pressing "BEGIN ROTATION PROCESS" press “SHOW UPDATE TOKEN” button to get the `update_token`.

## Initialize PureKit with the update token

Move to PureKit configuration file and specify your `update_token`:

<UpdateInitializeSnippet/>

## Start migration

- Run the `update` method of the `RecordUpdater` class to create a new user `record`
- Save user's new `record` into your database.

<UpdateMigrationSnippet/>

**Note!** You don't need to ask your users for a new password.

**Note!** The SDK is able to work with two versions of a user's `record` (old and new). This means, if a user logs into your system when you do the migration, the PureKit SDK will verify their password without any problems.


## Download CLI

After you updated your database records, it's required to update (rotate) your application credentials. For security reasons, you need to use the [Virgil CLI utility](https://github.com/VirgilSecurity/virgil-cli).

**Download** the preferred CLI package with one of the links below:
- [Mac OS](https://github.com/VirgilSecurity/virgil-cli/releases)
- [FreeBSD](https://github.com/VirgilSecurity/virgil-cli/releases)
- [Linux OS](https://github.com/VirgilSecurity/virgil-cli/releases)
- [Windows OS](https://github.com/VirgilSecurity/virgil-cli/releases)


## Rotate app secret key

Use Virgil CLI `update-keys` command and your `update_token` to update the `app_secret_key` and `service_public_key`:

```bash
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

## Configure PureKit SDK with new credentials

Move to PureKit SDK configuration and replace your previous `app_secret_key`, `service_public_key` with a new one (same for the `app_token`). Delete `update_token` and previous `app_secret_key`, `service_public_key`.

<UpdateReplaceSnippet/>

# Uninstall PureKit

Use this workflow to move away from Pure without having to put your users through registering again. This can be carried out by decrypting the encrypted database backup (users password hashes included) and replacing the encrypted data with it.

## Prepare your recovery key

In order to recover the original password hashes, you need to prepare your recovery private key.

<Warning>

If you don't have a recovery key, then you have to ask your users to go through the registration process again to restore their passwords.

</Warning>

## Decrypt encrypted password hashes

Now use your recovery private key to get original password hashes:

<DecryptHashes />

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
