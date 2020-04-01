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
	"crypto/subtle"
	"errors"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/foundation"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
)

const DerivedSecretLength = 44

type PureCrypto struct {
	Crypto    *crypto.Crypto
	pheCipher *phe.PheCipher
}

func NewPureCrypto(crypto *crypto.Crypto) *PureCrypto {

	cipher := phe.NewPheCipher()
	cipher.SetRandom(random)
	return &PureCrypto{
		Crypto:    crypto,
		pheCipher: cipher,
	}
}

func (p *PureCrypto) EncryptCellKey(
	plaintext []byte,
	recipients []crypto.PublicKey,
	signingKey crypto.PrivateKey) (*PureCryptoData, error) {

	if len(recipients) == 0 {
		return nil, errors.New("no recipients provided")
	}
	gcm := foundation.NewAes256Gcm()
	cipher := foundation.NewRecipientCipher()
	cipher.SetEncryptionCipher(gcm)
	cipher.SetRandom(random)
	if err := cipher.AddSigner(signingKey.Identifier(), signingKey.Unwrap()); err != nil {
		return nil, err
	}

	for _, r := range recipients {
		if r == nil || len(r.Identifier()) == 0 || r.Unwrap() == nil {
			return nil, errors.New("invalid recipient provided")
		}
		cipher.AddKeyRecipient(r.Identifier(), r.Unwrap())
	}
	cipher.SetSignerHash(foundation.NewSha512())
	if err := cipher.StartSignedEncryption(uint(len(plaintext))); err != nil {
		return nil, err
	}

	cms := cipher.PackMessageInfo()
	body1, err := cipher.ProcessEncryption(plaintext)
	if err != nil {
		return nil, err
	}
	body2, err := cipher.FinishEncryption()
	if err != nil {
		return nil, err
	}
	body3, err := cipher.PackMessageInfoFooter()
	if err != nil {
		return nil, err
	}

	return &PureCryptoData{
		Cms:  cms,
		Body: append(body1, append(body2, body3...)...),
	}, nil
}

func (p *PureCrypto) DecryptCellKey(data *PureCryptoData, privateKey crypto.PrivateKey, verifyingKey crypto.PublicKey) ([]byte, error) {

	cipher := foundation.NewRecipientCipher()
	cipher.SetRandom(random)
	if err := cipher.StartVerifiedDecryptionWithKey(privateKey.Identifier(), privateKey.Unwrap(), data.Cms, []byte{}); err != nil {
		return nil, err
	}
	body1, err := cipher.ProcessDecryption(data.Body)
	if err != nil {
		return nil, err
	}
	body2, err := cipher.FinishDecryption()
	if err != nil {
		return nil, err
	}
	if !cipher.IsDataSigned() {
		return nil, errors.New("data is not signed")
	}

	signerInfos := cipher.SignerInfos()
	if !signerInfos.HasItem() && signerInfos.HasNext() {
		return nil, errors.New("signer is absent")
	}

	info := signerInfos.Item()
	if subtle.ConstantTimeCompare(info.SignerId(), verifyingKey.Identifier()) == 0 {
		return nil, errors.New("signer is absent")
	}
	if !cipher.VerifySignerInfo(info, verifyingKey.Unwrap()) {
		return nil, errors.New("signature is invalid")
	}
	return append(body1, body2...), nil
}

func (p *PureCrypto) AddRecipientsToCellKey(cms []byte, privateKey crypto.PrivateKey, publicKeys []crypto.PublicKey) ([]byte, error) {

	editor := foundation.NewMessageInfoEditor()
	editor.SetRandom(random)
	if err := editor.Unpack(cms); err != nil {
		return nil, err
	}

	if err := editor.Unlock(privateKey.Identifier(), privateKey.Unwrap()); err != nil {
		return nil, err
	}
	for _, key := range publicKeys {
		if err := editor.AddKeyRecipient(key.Identifier(), key.Unwrap()); err != nil {
			return nil, err
		}
	}
	return editor.Pack(), nil
}

func (p *PureCrypto) DeleteRecipientsFromCellKey(cms []byte, publicKeys []crypto.PublicKey) ([]byte, error) {
	editor := foundation.NewMessageInfoEditor()
	editor.SetRandom(random)
	if err := editor.Unpack(cms); err != nil {
		return nil, err
	}

	for _, key := range publicKeys {
		editor.RemoveKeyRecipient(key.Identifier())
	}
	return editor.Pack(), nil
}

func (p *PureCrypto) ExtractPublicKeysIdsFromCellKey(cms []byte) ([][]byte, error) {

	serializer := foundation.NewMessageInfoDerSerializer()
	serializer.SetupDefaults()
	info, err := serializer.Deserialize(cms)
	if err != nil {
		return nil, err
	}
	keyList := info.KeyRecipientInfoList()
	var res [][]byte
	for keyList != nil && keyList.HasItem() {
		res = append(res, keyList.Item().RecipientId())
		if keyList.HasNext() {
			keyList = keyList.Next()
		} else {
			keyList = nil
		}
	}
	return res, nil
}

func (p *PureCrypto) GenerateSymmetricOneTimeKey() ([]byte, error) {
	return random.Random(DerivedSecretLength)
}

func (p *PureCrypto) ComputeSymmetricKeyId(key []byte) ([]byte, error) {
	return p.Crypto.Hash(key, crypto.Sha512)
}

func (p *PureCrypto) EncryptSymmetricWithOneTimeKey(plaintext, ad, key []byte) ([]byte, error) {

	if len(key) != DerivedSecretLength {
		return nil, errors.New("invalid key length")
	}
	cipher := foundation.NewAes256Gcm()
	cipher.SetKey(key[:cipher.GetKeyLen()])
	cipher.SetNonce(key[cipher.GetKeyLen():])
	ciphertext, tag, err := cipher.AuthEncrypt(plaintext, ad)
	if err != nil {
		return nil, err
	}
	return append(ciphertext, tag...), nil
}
func (p *PureCrypto) DecryptSymmetricWithOneTimeKey(ciphertext, ad, key []byte) ([]byte, error) {
	if len(key) != DerivedSecretLength {
		return nil, errors.New("invalid key length")
	}
	cipher := foundation.NewAes256Gcm()
	cipher.SetKey(key[:cipher.GetKeyLen()])
	cipher.SetNonce(key[cipher.GetKeyLen():])
	return cipher.AuthDecrypt(ciphertext, ad, []byte{})
}

func (p *PureCrypto) EncryptSymmetricWithNewNonce(plaintext, ad, key []byte) ([]byte, error) {
	return p.pheCipher.AuthEncrypt(plaintext, ad, key)
}

func (p *PureCrypto) DecryptSymmetricWithNewNonce(ciphertext, ad, key []byte) ([]byte, error) {
	return p.pheCipher.AuthDecrypt(ciphertext, ad, key)
}
func (p *PureCrypto) GenerateUserKey() (crypto.PrivateKey, error) {
	return p.Crypto.GenerateKeypairForType(crypto.Ed25519)
}

func (p *PureCrypto) GenerateRoleKey() (crypto.PrivateKey, error) {
	return p.Crypto.GenerateKeypairForType(crypto.Ed25519)
}

func (p *PureCrypto) GenerateCellKey() (crypto.PrivateKey, error) {
	return p.Crypto.GenerateKeypairForType(crypto.Ed25519)
}

func (p *PureCrypto) ImportPrivateKey(data []byte) (crypto.PrivateKey, error) {
	return p.Crypto.ImportPrivateKey(data)
}
func (p *PureCrypto) ImportPublicKey(data []byte) (crypto.PublicKey, error) {
	return p.Crypto.ImportPublicKey(data)
}

func (p *PureCrypto) ExportPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	return p.Crypto.ExportPrivateKey(key)
}

func (p *PureCrypto) ExportPublicKey(key crypto.PublicKey) ([]byte, error) {
	return p.Crypto.ExportPublicKey(key)
}

func (p *PureCrypto) EncryptForBackup(data []byte, encryptKey crypto.PublicKey, signingKey crypto.PrivateKey) ([]byte, error) {
	return p.Crypto.SignThenEncrypt(data, signingKey, encryptKey)
}

func (p *PureCrypto) DecryptBackup(data []byte, decryptKey crypto.PrivateKey, verifyKey crypto.PublicKey) ([]byte, error) {
	return p.Crypto.DecryptThenVerify(data, decryptKey, verifyKey)
}

func (p *PureCrypto) EncryptData(data []byte, signingKey crypto.PrivateKey, recipients ...crypto.PublicKey) ([]byte, error) {
	return p.Crypto.SignThenEncrypt(data, signingKey, recipients...)
}
func (p *PureCrypto) DecryptData(data []byte, decryptionKey crypto.PrivateKey, verificationKey crypto.PublicKey) ([]byte, error) {
	return p.Crypto.DecryptThenVerify(data, decryptionKey, verificationKey)
}

func (p *PureCrypto) EncryptRolePrivateKey(data []byte, encryptKey crypto.PublicKey, signingKey crypto.PrivateKey) ([]byte, error) {
	return p.Crypto.SignThenEncrypt(data, signingKey, encryptKey)
}

func (p *PureCrypto) DecryptRolePrivateKey(data []byte, decryptKey crypto.PrivateKey, verifyKey crypto.PublicKey) ([]byte, error) {
	return p.Crypto.DecryptThenVerify(data, decryptKey, verifyKey)
}

func (p *PureCrypto) ComputePasswordHash(password string) ([]byte, error) {
	return p.Crypto.Hash([]byte(password), crypto.Sha512)
}
