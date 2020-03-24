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
	"encoding/base64"
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/foundation"

	"github.com/pkg/errors"

	"google.golang.org/protobuf/proto"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/models"
	"github.com/VirgilSecurity/virgil-purekit-go/v3/storage"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
)

type Pure struct {
	CurrentVersion     uint32
	PureCrypto         *PureCrypto
	Storage            storage.PureStorage
	Buppk              crypto.PublicKey
	Oskp               crypto.PrivateKey
	ExternalPublicKeys map[string][]crypto.PublicKey
	PheManager         *PheManager
	KmsManager         *KmsManager
}

const (
	DefaultGrantTTL = time.Hour
)

func NewPure(context *Context) (*Pure, error) {

	p := &Pure{
		PureCrypto:         NewPureCrypto(context.Crypto),
		Storage:            context.Storage,
		Buppk:              context.Buppk,
		Oskp:               context.NonRotatableSecrets.Oksp,
		ExternalPublicKeys: context.ExternalPublicKeys,
	}
	pheMgr, err := NewPheManager(context)
	if err != nil {
		return nil, err
	}
	kmsMgr, err := NewKmsManager(context)
	if err != nil {
		return nil, err
	}
	p.PheManager = pheMgr
	p.KmsManager = kmsMgr

	if context.UpdateToken != nil {
		p.CurrentVersion = context.PublicKey.Version + 1
	} else {
		p.CurrentVersion = context.PublicKey.Version
	}

	return p, nil
}

func (p *Pure) RegisterUser(userID, password string) error {
	_, _, _, err := p.registerUserInternal(userID, password)
	return err
}

func (p *Pure) AuthenticateUser(userID, password string, sessionParams *SessionParameters) (*AuthResult, error) {

	user, err := p.Storage.SelectUser(userID)
	if err != nil {
		return nil, errors.Wrap(err, "select failed")
	}
	passHash, err := p.PureCrypto.ComputePasswordHash(password)
	if err != nil {
		return nil, err
	}
	phek, err := p.PheManager.ComputePheKey(user, passHash)
	if err != nil {
		return nil, errors.Wrap(err, "compute phe key failed")
	}

	uskData, err := p.PureCrypto.DecryptSymmetricWithNewNonce(user.EncryptedUsk, []byte{}, phek)
	if err != nil {
		return nil, err
	}
	ukp, err := p.PureCrypto.ImportPrivateKey(uskData)
	if err != nil {
		return nil, err
	}
	return p.authenticateUserInternal(user, ukp, phek, sessionParams)
}

func (p *Pure) InvalidateEncryptedUserGrant(encryptedGrant string) error {
	deserializedGrant, err := p.deserializeEncryptedGrant(encryptedGrant)
	if err != nil {
		return err
	}
	if _, err := p.decryptPheKeyFromEncryptedGrant(deserializedGrant); err != nil {
		return err
	}
	return p.Storage.DeleteGrantKey(deserializedGrant.EncryptedGrantHeader.UserId, deserializedGrant.EncryptedGrantHeader.KeyId)
}

func (p *Pure) CreateUserGrantAsAdmin(userID string, bupsk crypto.PrivateKey, ttl time.Duration) (*models.PureGrant, error) {
	user, err := p.Storage.SelectUser(userID)
	if err != nil {
		return nil, err
	}

	usk, err := p.PureCrypto.DecryptBackup(user.EncryptedUskBackup, bupsk, p.Oskp.PublicKey())
	if err != nil {
		return nil, err
	}
	upk, err := p.PureCrypto.ImportPrivateKey(usk)
	if err != nil {
		return nil, err
	}

	creationDate := time.Now()
	expirationDate := creationDate.Add(ttl)

	return &models.PureGrant{
		UKP:            upk,
		UserID:         userID,
		CreationDate:   creationDate,
		ExpirationDate: expirationDate,
	}, nil
}

func (p *Pure) RecoverUser(userID, newPassword string) error {

	user, err := p.Storage.SelectUser(userID)
	if err != nil {
		return err
	}
	oldHash, err := p.KmsManager.RecoverPwd(user)
	if err != nil {
		return err
	}
	oldPhek, err := p.PheManager.ComputePheKey(user, oldHash)
	if err != nil {
		return err
	}
	privateKeyData, err := p.PureCrypto.DecryptSymmetricWithNewNonce(user.EncryptedUsk, []byte{}, oldPhek)
	if err != nil {
		return err
	}
	return p.changeUserPasswordInternal(user, privateKeyData, newPassword)
}

func (p *Pure) DeleteUser(userID string) error {
	return p.Storage.DeleteUser(userID, true)
}

func (p *Pure) PerformRotation() (*RotationResults, error) {
	if p.CurrentVersion <= 1 {
		return &RotationResults{0, 0}, nil
	}

	usersRotated := uint64(0)
	grantsRotated := uint64(0)
	for {
		users, err := p.Storage.SelectUsersByVersion(p.CurrentVersion - 1)
		if err != nil {
			return nil, err
		}
		var newRecords []*models.UserRecord
		var newRecord []byte
		var newWrap []byte
		for _, user := range users {
			if user.RecordVersion != p.CurrentVersion-1 {
				return nil, errors.New("record version mismatch")
			}
			newRecord, err = p.PheManager.PerformRotation(user.PheRecord)
			if err != nil {
				return nil, err
			}
			newWrap, err = p.KmsManager.PerformPwdRotation(user.PasswordRecoveryWrap)
			if err != nil {
				return nil, err
			}

			newUserRecord := &models.UserRecord{
				UserID:               user.UserID,
				PheRecord:            newRecord,
				RecordVersion:        p.CurrentVersion,
				UPK:                  user.UPK,
				EncryptedUsk:         user.EncryptedUsk,
				EncryptedUskBackup:   user.EncryptedUskBackup,
				BackupPwdHash:        user.BackupPwdHash,
				PasswordRecoveryWrap: newWrap,
				PasswordRecoveryBlob: user.PasswordRecoveryBlob,
			}
			newRecords = append(newRecords, newUserRecord)

		}
		if err = p.Storage.UpdateUsers(newRecords, p.CurrentVersion-1); err != nil {
			return nil, err
		}
		if len(newRecords) > 0 {
			usersRotated += uint64(len(newRecords))
		} else {
			break
		}

	}
	for {
		grantKeys, err := p.Storage.SelectGrantKeys(p.CurrentVersion - 1)
		if err != nil {
			return nil, err
		}
		var updatedGrantKeys []*models.GrantKey
		var newWrap []byte
		for _, gk := range grantKeys {
			if gk.RecordVersion != p.CurrentVersion-1 {
				return nil, errors.New("grant version mismatch")
			}
			newWrap, err = p.KmsManager.PerformGrantRotation(gk.EncryptedGrantKeyWrap)
			if err != nil {
				return nil, err
			}

			newGrantKey := &models.GrantKey{
				UserID:                gk.UserID,
				KeyID:                 gk.KeyID,
				RecordVersion:         p.CurrentVersion,
				EncryptedGrantKeyWrap: newWrap,
				EncryptedGrantKeyBlob: gk.EncryptedGrantKeyBlob,
				CreationDate:          gk.CreationDate,
				ExpirationDate:        gk.ExpirationDate,
			}

			updatedGrantKeys = append(updatedGrantKeys, newGrantKey)
		}

		if err = p.Storage.UpdateGrantKeys(updatedGrantKeys...); err != nil {
			return nil, err
		}
		if len(updatedGrantKeys) > 0 {
			grantsRotated += uint64(len(updatedGrantKeys))
		} else {
			break
		}
	}
	return &RotationResults{
		UsersRotated:  usersRotated,
		GrantsRotated: grantsRotated,
	}, nil
}

func (p *Pure) Encrypt(userID, dataID string, plaintext []byte) ([]byte, error) {
	return p.encrypt(userID, dataID, nil, nil, nil, plaintext)
}

func (p *Pure) encrypt(userID, dataID string, otherUserIDs []string, roleNames []string, publicKeys []crypto.PublicKey, plainText []byte) ([]byte, error) {

	var (
		cpk         crypto.PublicKey
		userRecords []*models.UserRecord
		roles       []*models.Role
	)

	cellKey, err := p.Storage.SelectCellKey(userID, dataID)
	if err == nil {
		if cpk, err = p.PureCrypto.ImportPublicKey(cellKey.CPK); err != nil {
			return nil, err
		}
	} else if err == storage.ErrorNotFound {
		var recipientList []crypto.PublicKey
		recipientList = append(recipientList, publicKeys...)
		var userIds []string
		userIds = append(userIds, otherUserIDs...)
		userIds = append(userIds, userID)

		userRecords, err = p.Storage.SelectUsers(userIds...)
		if err != nil {
			return nil, err
		}
		var otherUpk crypto.PublicKey
		for _, ur := range userRecords {
			otherUpk, err = p.PureCrypto.ImportPublicKey(ur.UPK)
			if err != nil {
				return nil, err
			}
			recipientList = append(recipientList, otherUpk)
		}

		roles, err = p.Storage.SelectRoles(roleNames...)
		if err != nil {
			return nil, err
		}
		var rpk crypto.PublicKey
		for _, role := range roles {
			rpk, err = p.PureCrypto.ImportPublicKey(role.RPK)
			if err != nil {
				return nil, err
			}
			recipientList = append(recipientList, rpk)
		}

		if p.ExternalPublicKeys[dataID] != nil {
			recipientList = append(recipientList, p.ExternalPublicKeys[dataID]...)
		}

		var (
			ckp              crypto.PrivateKey
			cpkData          []byte
			cskData          []byte
			encryptedCskData *PureCryptoData
		)

		ckp, err = p.PureCrypto.GenerateCellKey()
		if err != nil {
			return nil, err
		}
		cpkData, err = p.PureCrypto.ExportPublicKey(ckp.PublicKey())
		if err != nil {
			return nil, err
		}
		cskData, err = p.PureCrypto.ExportPrivateKey(ckp)
		if err != nil {
			return nil, err
		}
		encryptedCskData, err = p.PureCrypto.EncryptCellKey(cskData, recipientList, p.Oskp)
		if err != nil {
			return nil, err
		}

		cellKey := &models.CellKey{
			UserID:           userID,
			DataID:           dataID,
			CPK:              cpkData,
			EncryptedCskCms:  encryptedCskData.Cms,
			EncryptedCskBody: encryptedCskData.Body,
		}

		if err = p.Storage.InsertCellKey(cellKey); err != nil {
			if err == storage.ErrorAlreadyExists {
				cellKey, err = p.Storage.SelectCellKey(userID, dataID)
				if err != nil {
					return nil, err
				}
				if cpk, err = p.PureCrypto.ImportPublicKey(cellKey.CPK); err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		} else {
			cpk = ckp.PublicKey()
		}
	} else {
		return nil, err
	}
	return p.PureCrypto.EncryptData(plainText, p.Oskp, cpk)
}

func (p *Pure) Decrypt(grant *models.PureGrant, ownerUserID, dataID string, ciphertext []byte) ([]byte, error) {
	userID := ownerUserID
	if userID == "" {
		userID = grant.UserID
	}
	cellKey, err := p.Storage.SelectCellKey(userID, dataID)
	if err != nil {
		return nil, err
	}
	pureCryptoData := &PureCryptoData{
		Cms:  cellKey.EncryptedCskCms,
		Body: cellKey.EncryptedCskBody,
	}

	csk, err := p.PureCrypto.DecryptCellKey(pureCryptoData, grant.UKP, p.Oskp.PublicKey())

	var roleAssignments []*models.RoleAssignment
	var publicKeysIds [][]byte
	if err != nil {
		fErr, ok := err.(*foundation.FoundationError)
		if !ok || fErr.Code != foundation.FoundationErrorErrorKeyRecipientIsNotFound {
			return nil, err
		}

		roleAssignments, err = p.Storage.SelectRoleAssignments(grant.UserID)
		if err != nil {
			return nil, err
		}

		publicKeysIds, err = p.PureCrypto.ExtractPublicKeysIdsFromCellKey(cellKey.EncryptedCskCms)
		if err != nil {
			return nil, err
		}
		var rskData []byte
		var rkp crypto.PrivateKey
		for _, ra := range roleAssignments {
			if contains(publicKeysIds, ra.PublicKeyID) {
				rskData, err = p.PureCrypto.DecryptRolePrivateKey(ra.EncryptedRsk, grant.UKP, p.Oskp.PublicKey())
				if err != nil {
					return nil, err
				}
				rkp, err = p.PureCrypto.ImportPrivateKey(rskData)
				if err != nil {
					return nil, err
				}
				csk, err = p.PureCrypto.DecryptCellKey(pureCryptoData, rkp, p.Oskp.PublicKey())
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if csk == nil {
		return nil, errors.New("user has no access to data")
	}

	ckp, err := p.PureCrypto.ImportPrivateKey(csk)
	if err != nil {
		return nil, err
	}
	return p.PureCrypto.DecryptData(ciphertext, ckp, p.Oskp.PublicKey())
}

func (p *Pure) Share(grant *models.PureGrant, dataID string, otherUserIds []string, publicKeys []crypto.PublicKey) error {
	keys, err := p.keysWithOthers(publicKeys, otherUserIds)
	if err != nil {
		return err
	}
	cellKey, err := p.Storage.SelectCellKey(grant.UserID, dataID)
	if err != nil {
		return err
	}
	encryptedCskCms, err := p.PureCrypto.AddRecipientsToCellKey(cellKey.EncryptedCskCms, grant.UKP, keys)
	if err != nil {
		return err
	}
	cellKey.EncryptedCskCms = encryptedCskCms
	return p.Storage.UpdateCellKey(cellKey)
}

func (p *Pure) Unshare(ownerUserID, dataID string, otherUserIDs []string, publicKeys []crypto.PublicKey) error {
	keys, err := p.keysWithOthers(publicKeys, otherUserIDs)
	if err != nil {
		return err
	}
	cellKey, err := p.Storage.SelectCellKey(ownerUserID, dataID)
	if err != nil {
		return err
	}

	encryptedCskCms, err := p.PureCrypto.DeleteRecipientsFromCellKey(cellKey.EncryptedCskCms, keys)
	if err != nil {
		return err
	}
	cellKey.EncryptedCskCms = encryptedCskCms
	return p.Storage.UpdateCellKey(cellKey)
}

func (p *Pure) CreateRole(roleName string, userIds ...string) error {
	roleKey, err := p.PureCrypto.GenerateRoleKey()
	if err != nil {
		return err
	}
	rpk, err := p.PureCrypto.ExportPublicKey(roleKey.PublicKey())
	if err != nil {
		return err
	}
	rsk, err := p.PureCrypto.ExportPrivateKey(roleKey)
	if err != nil {
		return err
	}
	role := &models.Role{
		RoleName: roleName,
		RPK:      rpk,
	}
	if err = p.Storage.InsertRole(role); err != nil {
		return err
	}

	return p.AssignRole(roleName, roleKey.Identifier(), rsk, userIds...)
}

func (p *Pure) AssignRoleWithGrant(roleName string, grant *models.PureGrant, userIds ...string) error {
	roleAssignment, err := p.Storage.SelectRoleAssignment(roleName, grant.UserID)
	if err != nil {
		return err
	}
	rskData, err := p.PureCrypto.DecryptRolePrivateKey(roleAssignment.EncryptedRsk, grant.UKP, p.Oskp.PublicKey())
	if err != nil {
		return err
	}
	return p.AssignRole(roleName, roleAssignment.PublicKeyID, rskData, userIds...)
}

func (p *Pure) UnassignRole(roleName string, userIds ...string) error {
	return p.Storage.DeleteRoleAssignments(roleName, userIds...)
}

func (p *Pure) AssignRole(roleName string, publicKeyID []byte, rskData []byte, userIds ...string) error {
	users, err := p.Storage.SelectUsers(userIds...)
	if err != nil {
		return err
	}
	roleAssignments := make([]*models.RoleAssignment, 0, len(userIds))
	for _, u := range users {
		upk, err := p.PureCrypto.ImportPublicKey(u.UPK)
		if err != nil {
			return err
		}
		encryptedRsk, err := p.PureCrypto.EncryptRolePrivateKey(rskData, upk, p.Oskp)
		if err != nil {
			return err
		}
		roleAssignment := &models.RoleAssignment{
			RoleName:     roleName,
			UserID:       u.UserID,
			PublicKeyID:  publicKeyID,
			EncryptedRsk: encryptedRsk,
		}
		roleAssignments = append(roleAssignments, roleAssignment)
	}
	return p.Storage.InsertRoleAssignments(roleAssignments...)
}

func (p *Pure) ShareToRoles(grant *models.PureGrant, dataID string, roleNames []string) error {
	roles, err := p.Storage.SelectRoles(roleNames...)
	if err != nil {
		return err
	}
	roleKeys := make([]crypto.PublicKey, 0, len(roles))
	for _, r := range roles {
		pk, err := p.PureCrypto.ImportPublicKey(r.RPK)
		if err != nil {
			return err
		}
		roleKeys = append(roleKeys, pk)
	}
	return p.Share(grant, dataID, nil, roleKeys)
}

func (p *Pure) ShareToRole(grant *models.PureGrant, dataID string, roleName string) error {
	return p.ShareToRoles(grant, dataID, []string{roleName})
}

func (p *Pure) keysWithOthers(publicKeys []crypto.PublicKey, otherUserIds []string) ([]crypto.PublicKey, error) {
	keys := make([]crypto.PublicKey, len(publicKeys))
	copy(keys, publicKeys)

	if len(otherUserIds) == 0 {
		return keys, nil
	}
	otherUserRecords, err := p.Storage.SelectUsers(otherUserIds...)
	if err != nil {
		return nil, err
	}
	for _, rec := range otherUserRecords {
		upk, err := p.PureCrypto.ImportPublicKey(rec.UPK)
		if err != nil {
			return nil, err
		}
		keys = append(keys, upk)
	}
	return keys, nil
}

func (p *Pure) deserializeEncryptedGrant(encryptedGrant string) (*DeserializedEncryptedGrant, error) {
	encryptedGrantData, err := base64.StdEncoding.DecodeString(encryptedGrant)
	if err != nil {
		return nil, err
	}
	encryptedGrantProto := &protos.EncryptedGrant{}
	if err := proto.Unmarshal(encryptedGrantData, encryptedGrantProto); err != nil {
		return nil, err
	}
	encryptedGrantHeaderProto := &protos.EncryptedGrantHeader{}
	if err := proto.Unmarshal(encryptedGrantProto.Header, encryptedGrantHeaderProto); err != nil {
		return nil, err
	}
	return &DeserializedEncryptedGrant{
		EncryptedGrant:       encryptedGrantProto,
		EncryptedGrantHeader: encryptedGrantHeaderProto,
	}, nil
}

func (p *Pure) decryptPheKeyFromEncryptedGrant(grant *DeserializedEncryptedGrant) ([]byte, error) {
	grantKey, err := p.Storage.SelectGrantKey(grant.EncryptedGrantHeader.UserId, grant.EncryptedGrantHeader.KeyId)
	if err != nil {
		return nil, err
	}

	if grantKey.ExpirationDate < uint64(time.Now().Unix()) {
		return nil, errors.New("grant key expired")
	}

	grantKeyRaw, err := p.KmsManager.RecoverGrantKey(grantKey, grant.EncryptedGrant.Header)
	if err != nil {
		return nil, err
	}

	return p.PureCrypto.DecryptSymmetricWithOneTimeKey(grant.EncryptedGrant.EncryptedPhek, grant.EncryptedGrant.Header, grantKeyRaw)
}

func (p *Pure) DecryptGrantFromUser(encryptedGrant string) (*models.PureGrant, error) {
	grant, err := p.deserializeEncryptedGrant(encryptedGrant)
	if err != nil {
		return nil, err
	}
	phek, err := p.decryptPheKeyFromEncryptedGrant(grant)
	if err != nil {
		return nil, err
	}
	user, err := p.Storage.SelectUser(grant.EncryptedGrantHeader.UserId)
	if err != nil {
		return nil, err
	}
	usk, err := p.PureCrypto.DecryptSymmetricWithNewNonce(user.EncryptedUsk, []byte{}, phek)
	if err != nil {
		return nil, err
	}
	ukp, err := p.PureCrypto.ImportPrivateKey(usk)
	if err != nil {
		return nil, err
	}

	return &models.PureGrant{
		UKP:            ukp,
		UserID:         grant.EncryptedGrantHeader.UserId,
		SessionID:      grant.EncryptedGrantHeader.SessionId,
		CreationDate:   time.Unix(int64(grant.EncryptedGrantHeader.CreationDate), 0),
		ExpirationDate: time.Unix(int64(grant.EncryptedGrantHeader.ExpirationDate), 0),
	}, nil
}

func (p *Pure) ChangeUserPassword(userID, oldPassword, newPassword string) error {
	user, err := p.Storage.SelectUser(userID)
	if err != nil {
		return err
	}
	oldPassHash, err := p.PureCrypto.ComputePasswordHash(oldPassword)
	if err != nil {
		return err
	}
	oldPhek, err := p.PheManager.ComputePheKey(user, oldPassHash)
	if err != nil {
		return err
	}
	privateKeyData, err := p.PureCrypto.DecryptSymmetricWithNewNonce(user.EncryptedUsk, []byte{}, oldPhek)
	if err != nil {
		return err
	}
	return p.changeUserPasswordInternal(user, privateKeyData, newPassword)
}

func (p *Pure) ChangeUserPasswordWithGrant(grant *models.PureGrant, newPassword string) error {
	user, err := p.Storage.SelectUser(grant.UserID)
	if err != nil {
		return err
	}
	sk, err := p.PureCrypto.ExportPrivateKey(grant.UKP)
	if err != nil {
		return err
	}
	return p.changeUserPasswordInternal(user, sk, newPassword)
}

func (p *Pure) registerUserInternal(userID, password string) (*models.UserRecord, crypto.PrivateKey, []byte, error) {
	passwordHash, err := p.PureCrypto.ComputePasswordHash(password)
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedPasswordHash, err := p.PureCrypto.EncryptForBackup(passwordHash, p.Buppk, p.Oskp)
	if err != nil {
		return nil, nil, nil, err
	}
	pwdRecoveryData, err := p.KmsManager.GeneratePwdRecoveryData(passwordHash)
	if err != nil {
		return nil, nil, nil, err
	}
	record, accountKey, err := p.PheManager.GetEnrollment(passwordHash)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "GetEnrollment failed")
	}
	ukp, err := p.PureCrypto.GenerateUserKey()
	if err != nil {
		return nil, nil, nil, err
	}
	uskData, err := p.PureCrypto.ExportPrivateKey(ukp)
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedUsk, err := p.PureCrypto.EncryptSymmetricWithNewNonce(uskData, []byte{}, accountKey)
	if err != nil {
		return nil, nil, nil, err
	}

	encryptedUskBackup, err := p.PureCrypto.EncryptForBackup(uskData, p.Buppk, p.Oskp)
	if err != nil {
		return nil, nil, nil, err
	}
	publicKey, err := p.PureCrypto.ExportPublicKey(ukp.PublicKey())
	if err != nil {
		return nil, nil, nil, err
	}

	userRecord := &models.UserRecord{
		UserID:               userID,
		PheRecord:            record,
		RecordVersion:        p.CurrentVersion,
		UPK:                  publicKey,
		EncryptedUsk:         encryptedUsk,
		EncryptedUskBackup:   encryptedUskBackup,
		BackupPwdHash:        encryptedPasswordHash,
		PasswordRecoveryWrap: pwdRecoveryData.Wrap,
		PasswordRecoveryBlob: pwdRecoveryData.Blob,
	}

	if err = p.Storage.InsertUser(userRecord); err != nil {
		return nil, nil, nil, errors.Wrap(err, "InsertUser failed")
	}

	return userRecord, ukp, accountKey, nil
}

func (p *Pure) authenticateUserInternal(
	record *models.UserRecord,
	ukp crypto.PrivateKey,
	phek []byte,
	sessionParams *SessionParameters) (*AuthResult, error) {

	var ttl time.Duration
	var sessionID string
	if sessionParams == nil {
		ttl = DefaultGrantTTL
	} else {
		ttl = sessionParams.TTL
		sessionID = sessionParams.SessionID
	}

	creationDate := time.Now()
	expirationDate := creationDate.Add(ttl)

	grant := &models.PureGrant{
		UKP:            ukp,
		UserID:         record.UserID,
		SessionID:      sessionID,
		CreationDate:   creationDate,
		ExpirationDate: expirationDate,
	}

	grantKeyRaw, err := p.PureCrypto.GenerateSymmetricOneTimeKey()
	if err != nil {
		return nil, err
	}
	keyID, err := p.PureCrypto.ComputeSymmetricKeyId(grantKeyRaw)
	if err != nil {
		return nil, err
	}

	grantHeader := &protos.EncryptedGrantHeader{
		UserId:         record.UserID,
		SessionId:      sessionID,
		KeyId:          keyID,
		CreationDate:   uint64(creationDate.Unix()),
		ExpirationDate: uint64(expirationDate.Unix()),
	}
	headerBytes, err := proto.Marshal(grantHeader)
	if err != nil {
		return nil, err
	}

	grantWrap, err := p.KmsManager.GenerateGrantKeyEncryptionData(grantKeyRaw, headerBytes)
	if err != nil {
		return nil, err
	}

	grantKey := &models.GrantKey{
		UserID:                record.UserID,
		KeyID:                 keyID,
		RecordVersion:         p.CurrentVersion,
		EncryptedGrantKeyWrap: grantWrap.Wrap,
		EncryptedGrantKeyBlob: grantWrap.Blob,
		CreationDate:          uint64(creationDate.Unix()),
		ExpirationDate:        uint64(expirationDate.Unix()),
	}

	if err = p.Storage.InsertGrantKey(grantKey); err != nil {
		return nil, err
	}

	encryptedPhek, err := p.PureCrypto.EncryptSymmetricWithOneTimeKey(phek, headerBytes, grantKeyRaw)
	if err != nil {
		return nil, err
	}

	encryptedGrant := &protos.EncryptedGrant{
		Version:       storage.CurrentEncryptedGrantVersion,
		EncryptedPhek: encryptedPhek,
		Header:        headerBytes,
	}

	encryptedGrantBytes, err := proto.Marshal(encryptedGrant)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		Grant:          grant,
		EncryptedGrant: base64.StdEncoding.EncodeToString(encryptedGrantBytes),
	}, nil
}

func (p *Pure) changeUserPasswordInternal(user *models.UserRecord, privateKeyData []byte, password string) error {
	newPasswordHash, err := p.PureCrypto.ComputePasswordHash(password)
	if err != nil {
		return err
	}

	record, key, err := p.PheManager.GetEnrollment(newPasswordHash)
	if err != nil {
		return err
	}
	kmsData, err := p.KmsManager.GeneratePwdRecoveryData(newPasswordHash)
	if err != nil {
		return err
	}
	newEncryptedUsk, err := p.PureCrypto.EncryptSymmetricWithNewNonce(privateKeyData, []byte{}, key)
	if err != nil {
		return err
	}
	encryptedPwdHash, err := p.PureCrypto.EncryptForBackup(newPasswordHash, p.Buppk, p.Oskp)
	if err != nil {
		return err
	}
	rec := &models.UserRecord{
		UserID:               user.UserID,
		PheRecord:            record,
		RecordVersion:        p.CurrentVersion,
		UPK:                  user.UPK,
		EncryptedUsk:         newEncryptedUsk,
		EncryptedUskBackup:   user.EncryptedUskBackup,
		BackupPwdHash:        encryptedPwdHash,
		PasswordRecoveryWrap: kmsData.Wrap,
		PasswordRecoveryBlob: kmsData.Blob,
	}
	return p.Storage.UpdateUser(rec)
}

func contains(ids [][]byte, id []byte) bool {
	for _, idd := range ids {
		if subtle.ConstantTimeCompare(idd, id) == 1 {
			return true
		}
	}
	return false
}
