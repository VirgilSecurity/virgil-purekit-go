/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package purekit

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/clients"
	"github.com/VirgilSecurity/virgil-purekit-go/v3/storage"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/pkg/errors"
)

const (
	NmsPrefix       = "NM"
	BuppkPrefix     = "BU"
	SecretKeyPrefix = "SK"
	PublicKeyPrefix = "PK"
)

// Context holds & validates protocol input parameters
type Context struct {
	Crypto              *crypto.Crypto
	Version             uint32
	UpdateToken         *Credentials
	PublicKey           *Credentials
	SecretKey           *Credentials
	Buppk               crypto.PublicKey
	Storage             storage.PureStorage
	PheClient           *clients.PheClient
	KmsClient           *clients.KmsClient
	NonRotatableSecrets *NonRotatableSecrets
	ExternalPublicKeys  map[string][]crypto.PublicKey
	AppToken            string
}

//CreateContext validates input parameters and prepares them for being used in Protocol
func CreateContext(c *crypto.Crypto,
	at, nm, bu, sk, pk string,
	pureStorage storage.PureStorage,
	externalPublicKeys map[string][]string,
	pheServerAddress, kmsServerAddress string) (*Context, error) {

	if at == "" {
		return nil, errors.New("app token is mandatory")
	}

	res := &Context{}
	res.Crypto = c

	nmsCred, err := ParseCredentials(NmsPrefix, nm, false, 1)
	if err != nil {
		return nil, errors.Wrap(err, "invalid nms")
	}
	res.NonRotatableSecrets, err = GenerateNonRotatableSecrets(c, nmsCred.Payload1)
	if err != nil {
		return nil, errors.Wrap(err, "invalid nms")
	}
	buppkCreds, err := ParseCredentials(BuppkPrefix, bu, false, 1)
	if err != nil {
		return nil, errors.Wrap(err, "invalid Buppk")
	}
	res.Buppk, err = c.ImportPublicKey(buppkCreds.Payload1)
	if err != nil {
		return nil, errors.Wrap(err, "invalid Buppk")
	}
	res.SecretKey, err = ParseCredentials(SecretKeyPrefix, sk, true, 3)
	if err != nil {
		return nil, errors.Wrap(err, "invalid sk")
	}
	res.PublicKey, err = ParseCredentials(PublicKeyPrefix, pk, true, 2)
	if err != nil {
		return nil, errors.Wrap(err, "invalid publicKey")
	}

	if serializerDependentStorage, ok := pureStorage.(storage.SerializerDependentStorage); ok {
		serializer := &storage.ModelSerializer{
			SigningKey: res.NonRotatableSecrets.Vksp,
			Crypto:     c,
		}
		serializerDependentStorage.SetSerializer(serializer)
	}

	res.PheClient = &clients.PheClient{
		Client: &clients.Client{
			AppToken: at,
			URL:      pheServerAddress,
		}}

	res.KmsClient = &clients.KmsClient{
		Client: &clients.Client{
			AppToken: at,
			URL:      kmsServerAddress,
		}}

	res.Storage = pureStorage

	if externalPublicKeys != nil {
		res.ExternalPublicKeys = make(map[string][]crypto.PublicKey)
		for id, keys := range externalPublicKeys {
			publicKeys := make([]crypto.PublicKey, 0, len(keys))
			for _, keyStr := range keys {
				bKey, err := base64.StdEncoding.DecodeString(keyStr)
				if err != nil {
					return nil, err
				}
				key, err := c.ImportPublicKey(bKey)
				if err != nil {
					return nil, err
				}
				publicKeys = append(publicKeys, key)
			}
			res.ExternalPublicKeys[id] = publicKeys
		}
	}
	return res, nil
}

func CreateCloudContext(at, nm, bu, sk, pk string,
	externalPublicKeys map[string][]string,
	pheServiceAddress,
	pureServiceAddress,
	kmsServiceAddress string) (*Context, error) {

	c := &crypto.Crypto{}
	pureClient := &clients.PureClient{
		Client: &clients.Client{
			AppToken: at,
			URL:      pureServiceAddress,
		},
	}
	stor := &storage.VirgilCloudPureStorage{
		Client: pureClient,
	}
	return CreateContext(c, at, nm, bu, sk, pk, stor, externalPublicKeys, pheServiceAddress, kmsServiceAddress)
}

func CreateDefaultCloudContext(at, nm, bu, sk, pk string,
	externalPublicKeys map[string][]string) (*Context, error) {
	return CreateCloudContext(at, nm, bu, sk, pk, externalPublicKeys, clients.PheAPIURL, clients.PureAPIURL, clients.KmsAPIURL)
}

func ParseCredentials(prefix, creds string, versioned bool, numPayloads int) (*Credentials, error) {
	parts := strings.Split(creds, ".")
	numberOfParts := 1 + numPayloads
	if versioned {
		numberOfParts++
	}
	if len(parts) != numberOfParts || parts[0] != prefix {
		return nil, errors.New("credentials parsing error")
	}

	index := 1
	res := &Credentials{}
	if versioned {
		nVersion, err := strconv.Atoi(parts[index])
		if err != nil || nVersion < 0 {
			return nil, errors.Wrap(err, "credentials parsing error")
		}
		res.Version = uint32(nVersion)
		index++
	}

	payload1, err := base64.StdEncoding.DecodeString(parts[index])
	if err != nil {
		return nil, errors.Wrap(err, "credentials parsing error")
	}
	numPayloads--
	index++
	res.Payload1 = payload1
	if numPayloads > 0 {
		payload2, err := base64.StdEncoding.DecodeString(parts[index])
		if err != nil {
			return nil, errors.Wrap(err, "credentials parsing error")
		}
		numPayloads--
		index++
		res.Payload2 = payload2
	}

	if numPayloads > 0 {
		payload3, err := base64.StdEncoding.DecodeString(parts[index])
		if err != nil {
			return nil, errors.Wrap(err, "credentials parsing error")
		}
		res.Payload3 = payload3
	}
	return res, nil
}

func (c *Context) SetUpdateToken(updateToken string) error {
	token, err := ParseCredentials("UT", updateToken, true, 3)
	if err != nil {
		return err
	}
	if token.Version != c.PublicKey.Version+1 {
		return errors.New("update token version mismatch")
	}
	c.UpdateToken = token
	return nil
}
