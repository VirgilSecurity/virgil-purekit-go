# Virgil PureKit Go 

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-go.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Features](#features)  | [Benefits](#benefits) | [Installation](#installation) | [Resources](#resources) | [License](#license) | [Support](#support)

## Introduction

<img src="https://cdn.virgilsecurity.com/assets/images/github/logos/purekit/PureKit.png" width="20%" align="left" hspace="1" vspace="3">

</a>[Virgil Security](https://virgilsecurity.com) introduces [Virgil PureKit](https://virgilsecurity.com/purekit/) - an open-source security framework for enabling post-compromise protection for stored data. PureKit allows developers to protect users' passwords and personal data from hacking and securely share data.

The framework can be used within any database or login system that uses a password, so it’s applicable for a company of any industry or size.

### Password-Based Security

Virgil PureKit is based on the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that protects users' data and reduces the security risks associated with weak passwords.

PureKit brings data security to a new level in three ways:
1. **Replaces password hashing** in a way making it impossible to run offline and online attacks. By interacting with PHE Service, a standalone cryptographic service in Virgil Cloud dedicated to implement  PHE protocol, PureKit creates a unique user’s record that is associated with the user password. It is important to note that a user password is never transmitted to the PHE service in any form.
2. **Encrypts data with user’s personal encryption keys**. PureKit gives users a possibility to encrypt their data with personal encryption keys, and all keys can be revealed only after providing a correct password.
3. **Immediately invalidate stolen database**. Even if your database has been compromised it impossible to run offline attacks, to retrieve user password or decrypt data. At the same time, PureKit provides convenient and secure key rotation procedure, that allows you quickly update all your server keys without losing access to your data.

## Features

- Per-user data and files encryption
- Password protection against hacking
- Management of data encryption keys 
- Secure data and files sharing
- Role-based data encryption


## Benefits

- Users control data access
- Post-compromise security
- Password & data protection from online and offline attacks
- Replaces salting and hashing of passwords
- Zero knowledge of user passwords and secret keys
- Virgil Security has no access to your data
- Encryption occurs independently of database security
- Works with any database
- Stronger than encryption at-rest and TDE
- More secure than AWS and Google Key Management Systems (KMS)
- Instant invalidation of stolen databases
- Compliance with GDPR, HIPAA, PCI DSS and more

## Installation

Navigate to our [Developer Documentation](https://developer.virgilsecurity.com/docs/purekit) to install and start working with Virgil PureKit.

## Resources

- [PureKit Product Page](https://virgilsecurity.com/purekit/)
- [PureKit Documentation](https://developer.virgilsecurity.com/docs/purekit) - start integrating PureKit into your project with our detailed guides.
- [MariaDB Demo](https://github.com/VirgilSecurity/virgil-mariadb-demo) - a simple web application that illustrates how Virgil PureKit can be used with MariaDB to store and share data in the most secure way.
- [Virgil PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the Password-Hardened Encryption (PHE) protocol.

## License
This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information at our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send an email to our support team support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
