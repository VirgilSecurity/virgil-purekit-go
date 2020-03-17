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
	"fmt"

	"github.com/VirgilSecurity/virgil-purekit-go/clients"
	"github.com/VirgilSecurity/virgil-purekit-go/models"
	"github.com/VirgilSecurity/virgil-purekit-go/protos"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
)

type KmsManager struct {
	CurrentVersion      uint32
	PureCrypto          *PureCrypto
	PwdCurrentClient    *phe.UokmsClient
	PwdPreviousClient   *phe.UokmsClient
	GrantCurrentClient  *phe.UokmsClient
	grantPreviousClient *phe.UokmsClient
	HTTPKmsClient       *clients.KmsClient
	PwdKmsRotation      *phe.UokmsWrapRotation
	GrantKmsRotation    *phe.UokmsWrapRotation
}

const RecoverPwdAlias = "RECOVERY_PASSWORD"

func NewKmsManager(context *Context) (*KmsManager, error) {
	mgr := &KmsManager{
		PureCrypto:         NewPureCrypto(context.Crypto),
		PwdCurrentClient:   phe.NewUokmsClient(),
		GrantCurrentClient: phe.NewUokmsClient(),
		HTTPKmsClient:      context.KmsClient,
	}

	mgr.PwdCurrentClient.SetRandom(random)
	mgr.PwdCurrentClient.SetOperationRandom(random)
	mgr.GrantCurrentClient.SetRandom(random)
	mgr.GrantCurrentClient.SetOperationRandom(random)

	if context.UpdateToken != nil {
		mgr.CurrentVersion = context.PublicKey.Version + 1
		pwdUpdateToken := context.UpdateToken.Payload2
		mgr.PwdKmsRotation = phe.NewUokmsWrapRotation()
		mgr.PwdKmsRotation.SetOperationRandom(random)
		if err := mgr.PwdKmsRotation.SetUpdateToken(pwdUpdateToken); err != nil {
			return nil, err
		}
		mgr.PwdPreviousClient = phe.NewUokmsClient()
		mgr.PwdPreviousClient.SetOperationRandom(random)
		mgr.PwdPreviousClient.SetRandom(random)
		if err := mgr.PwdPreviousClient.SetKeys(context.SecretKey.Payload2, context.PublicKey.Payload2); err != nil {
			return nil, err
		}

		grantUpdateToken := context.UpdateToken.Payload3
		mgr.GrantKmsRotation = phe.NewUokmsWrapRotation()
		mgr.GrantKmsRotation.SetOperationRandom(random)
		if err := mgr.GrantKmsRotation.SetUpdateToken(grantUpdateToken); err != nil {
			return nil, err
		}

		mgr.grantPreviousClient = phe.NewUokmsClient()
		mgr.grantPreviousClient.SetOperationRandom(random)
		mgr.grantPreviousClient.SetRandom(random)
		if err := mgr.grantPreviousClient.SetKeysOneparty(context.SecretKey.Payload3); err != nil {
			return nil, err
		}
		priv, pub, err := mgr.PwdPreviousClient.RotateKeys(pwdUpdateToken)
		if err != nil {
			return nil, err
		}
		if err := mgr.PwdCurrentClient.SetKeys(priv, pub); err != nil {
			return nil, err
		}

		newGrantPrivate, err := mgr.grantPreviousClient.RotateKeysOneparty(grantUpdateToken)
		if err != nil {
			return nil, err
		}
		if err := mgr.GrantCurrentClient.SetKeysOneparty(newGrantPrivate); err != nil {
			return nil, err
		}
	} else {
		mgr.CurrentVersion = context.PublicKey.Version
		if err := mgr.PwdCurrentClient.SetKeys(context.SecretKey.Payload2, context.PublicKey.Payload2); err != nil {
			return nil, err
		}
		if err := mgr.GrantCurrentClient.SetKeysOneparty(context.SecretKey.Payload3); err != nil {
			return nil, err
		}
	}
	mgr.HTTPKmsClient = context.KmsClient
	return mgr, nil
}

func (k *KmsManager) GetPwdClient(kmsVersion uint32) (*phe.UokmsClient, error) {
	if kmsVersion == k.CurrentVersion {
		return k.PwdCurrentClient, nil
	} else if k.CurrentVersion == kmsVersion+1 && k.PwdPreviousClient != nil {
		return k.PwdPreviousClient, nil
	}
	return nil, fmt.Errorf("no pwd client with such kms version %d", kmsVersion)
}

func (k *KmsManager) GetGrantClient(kmsVersion uint32) (*phe.UokmsClient, error) {
	if kmsVersion == k.CurrentVersion {
		return k.GrantCurrentClient, nil
	} else if k.CurrentVersion == kmsVersion+1 && k.grantPreviousClient != nil {
		return k.grantPreviousClient, nil
	}
	return nil, fmt.Errorf("no grant client with such kms version %d", kmsVersion)
}

func (k *KmsManager) RecoverPwdSecret(record *models.UserRecord) ([]byte, error) {
	pwdClient, err := k.GetPwdClient(record.RecordVersion)
	if err != nil {
		return nil, err
	}
	deblindFactor, deblindRequest, err := pwdClient.GenerateDecryptRequest(record.PasswordRecoveryWrap)
	if err != nil {
		return nil, err
	}

	req := &protos.DecryptRequest{
		Version: record.RecordVersion,
		Alias:   RecoverPwdAlias,
		Request: deblindRequest,
	}
	resp, err := k.HTTPKmsClient.Decrypt(req)
	if err != nil {
		return nil, err
	}
	return pwdClient.ProcessDecryptResponse(record.PasswordRecoveryWrap, deblindRequest, resp.Response, deblindFactor, DerivedSecretLength)
}

func (k *KmsManager) RecoverGrantKeySecret(grantKey *models.GrantKey) ([]byte, error) {
	grantClient, err := k.GetGrantClient(grantKey.RecordVersion)
	if err != nil {
		return nil, err
	}
	return grantClient.DecryptOneparty(grantKey.EncryptedGrantKeyWrap, DerivedSecretLength)
}

func (k *KmsManager) RecoverGrantKey(grantKey *models.GrantKey, header []byte) ([]byte, error) {
	derivedSecret, err := k.RecoverGrantKeySecret(grantKey)
	if err != nil {
		return nil, err
	}
	return k.PureCrypto.DecryptSymmetricWithOneTimeKey(grantKey.EncryptedGrantKeyBlob, header, derivedSecret)
}

func (k *KmsManager) PerformPwdRotation(wrap []byte) ([]byte, error) {
	return k.PwdKmsRotation.UpdateWrap(wrap)
}

func (k *KmsManager) PerformGrantRotation(wrap []byte) ([]byte, error) {
	return k.GrantKmsRotation.UpdateWrap(wrap)
}

func (k *KmsManager) RecoverPwd(record *models.UserRecord) ([]byte, error) {
	derivedSecret, err := k.RecoverPwdSecret(record)
	if err != nil {
		return nil, err
	}
	return k.PureCrypto.DecryptSymmetricWithOneTimeKey(record.PasswordRecoveryBlob, make([]byte, 0), derivedSecret)
}

func (k *KmsManager) RecoverGrant(grant *models.GrantKey, header []byte) ([]byte, error) {
	derivedSecret, err := k.RecoverGrantKeySecret(grant)
	if err != nil {
		return nil, err
	}
	return k.PureCrypto.DecryptSymmetricWithOneTimeKey(grant.EncryptedGrantKeyBlob, header, derivedSecret)
}

func (k *KmsManager) GeneratePwdRecoveryData(passwordHash []byte) (*KmsEncryptedData, error) {
	return k.generateEncryptionData(passwordHash, make([]byte, 0), true)
}

func (k *KmsManager) GenerateGrantKeyEncryptionData(grantKey, header []byte) (*KmsEncryptedData, error) {
	return k.generateEncryptionData(grantKey, header, false)
}

func (k *KmsManager) generateEncryptionData(data, header []byte, isPwd bool) (*KmsEncryptedData, error) {
	var cli *phe.UokmsClient
	if isPwd {
		cli = k.PwdCurrentClient
	} else {
		cli = k.GrantCurrentClient
	}

	wrapBuf, keyBuf, err := cli.GenerateEncryptWrap(DerivedSecretLength)
	if err != nil {
		return nil, err
	}

	recoverBlob, err := k.PureCrypto.EncryptSymmetricWithOneTimeKey(data, header, keyBuf)
	if err != nil {
		return nil, err
	}
	return &KmsEncryptedData{
		Wrap: wrapBuf,
		Blob: recoverBlob,
	}, nil
}
