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

package storage

import (
	"github.com/VirgilSecurity/virgil-purekit-go/v3/models"
	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"google.golang.org/protobuf/proto"
)

type ModelSerializer struct {
	SigningKey crypto.PrivateKey
	Crypto     *crypto.Crypto
}

const (
	CurrentUserVersion                 = 1
	CurrentUserSignedVersion           = 1
	CurrentCellKeyVersion              = 1
	CurrentCellKeySignedVersion        = 1
	CurrentRoleVersion                 = 1
	CurrentRoleSignedVersion           = 1
	CurrentRoleAssignmentVersion       = 1
	CurrentRoleAssignmentSignedVersion = 1
	CurrentGrantKeyVersion             = 1
	CurrentGrantKeySignedVersion       = 1
	CurrentEncryptedGrantVersion       = 1
)

func (m *ModelSerializer) GenerateSignature(data []byte) ([]byte, error) {
	return m.Crypto.Sign(data, m.SigningKey)
}

func (m *ModelSerializer) ValidateSignature(data, signature []byte) error {
	return m.Crypto.VerifySignature(data, signature, m.SigningKey.PublicKey())
}

func (m *ModelSerializer) SerializeUserRecord(rec *models.UserRecord) (*protos.UserRecord, error) {

	enRec := &protos.EnrollmentRecord{}
	if err := proto.Unmarshal(rec.PheRecord, enRec); err != nil {
		return nil, err
	}

	urs := &protos.UserRecordSigned{
		Version:              CurrentUserSignedVersion,
		UserId:               rec.UserID,
		PheRecordNs:          enRec.Ns,
		PheRecordNc:          enRec.Nc,
		Upk:                  rec.UPK,
		EncryptedUsk:         rec.EncryptedUsk,
		EncryptedUskBackup:   rec.EncryptedUskBackup,
		BackupPwdHash:        rec.BackupPwdHash,
		PasswordRecoveryBlob: rec.PasswordRecoveryBlob,
	}

	userRecordSigned, err := proto.Marshal(urs)
	if err != nil {
		return nil, err
	}
	signature, err := m.GenerateSignature(userRecordSigned)
	if err != nil {
		return nil, err
	}
	userRecord := &protos.UserRecord{
		Version:              CurrentUserVersion,
		UserRecordSigned:     userRecordSigned,
		Signature:            signature,
		PheRecordT0:          enRec.T0,
		PheRecordT1:          enRec.T1,
		RecordVersion:        rec.RecordVersion,
		PasswordRecoveryWrap: rec.PasswordRecoveryWrap,
	}
	return userRecord, nil
}

func (m *ModelSerializer) ParseUserRecord(rec *protos.UserRecord) (*models.UserRecord, error) {

	if err := m.ValidateSignature(rec.UserRecordSigned, rec.Signature); err != nil {
		return nil, err
	}

	signed := &protos.UserRecordSigned{}
	if err := proto.Unmarshal(rec.UserRecordSigned, signed); err != nil {
		return nil, err
	}

	enRec := &protos.EnrollmentRecord{
		Ns: signed.PheRecordNs,
		Nc: signed.PheRecordNc,
		T0: rec.PheRecordT0,
		T1: rec.PheRecordT1,
	}

	pheRec, err := proto.Marshal(enRec)
	if err != nil {
		return nil, err
	}

	userRecord := &models.UserRecord{
		UserID:               signed.UserId,
		PheRecord:            pheRec,
		RecordVersion:        rec.RecordVersion,
		UPK:                  signed.Upk,
		EncryptedUsk:         signed.EncryptedUsk,
		EncryptedUskBackup:   signed.EncryptedUskBackup,
		BackupPwdHash:        signed.BackupPwdHash,
		PasswordRecoveryWrap: rec.PasswordRecoveryWrap,
		PasswordRecoveryBlob: signed.PasswordRecoveryBlob,
	}
	return userRecord, nil
}

func (m *ModelSerializer) SerializeCellKey(key *models.CellKey) (*protos.CellKey, error) {

	cks := &protos.CellKeySigned{
		Version:          CurrentCellKeySignedVersion,
		UserId:           key.UserID,
		DataId:           key.DataID,
		Cpk:              key.CPK,
		EncryptedCskCms:  key.EncryptedCskCms,
		EncryptedCskBody: key.EncryptedCskBody,
	}

	data, err := proto.Marshal(cks)
	if err != nil {
		return nil, err
	}

	signature, err := m.GenerateSignature(data)
	if err != nil {
		return nil, err
	}

	ck := &protos.CellKey{
		Version:       CurrentCellKeyVersion,
		CellKeySigned: data,
		Signature:     signature,
	}

	return ck, nil
}

func (m *ModelSerializer) ParseCellKey(key *protos.CellKey) (*models.CellKey, error) {

	if err := m.ValidateSignature(key.CellKeySigned, key.Signature); err != nil {
		return nil, err
	}

	cks := &protos.CellKeySigned{}
	if err := proto.Unmarshal(key.CellKeySigned, cks); err != nil {
		return nil, err
	}

	ck := &models.CellKey{
		UserID:           cks.UserId,
		DataID:           cks.DataId,
		CPK:              cks.Cpk,
		EncryptedCskCms:  cks.EncryptedCskCms,
		EncryptedCskBody: cks.EncryptedCskBody,
	}
	return ck, nil
}

func (m *ModelSerializer) SerializeRole(role *models.Role) (*protos.Role, error) {

	rs := &protos.RoleSigned{
		Version: CurrentRoleSignedVersion,
		Name:    role.RoleName,
		Rpk:     role.RPK,
	}

	data, err := proto.Marshal(rs)
	if err != nil {
		return nil, err
	}

	signature, err := m.GenerateSignature(data)
	if err != nil {
		return nil, err
	}

	r := &protos.Role{
		Version:    CurrentRoleVersion,
		RoleSigned: data,
		Signature:  signature,
	}

	return r, nil
}

func (m *ModelSerializer) ParseRole(role *protos.Role) (*models.Role, error) {

	if err := m.ValidateSignature(role.RoleSigned, role.Signature); err != nil {
		return nil, err
	}

	rs := &protos.RoleSigned{}
	if err := proto.Unmarshal(role.RoleSigned, rs); err != nil {
		return nil, err
	}

	r := &models.Role{
		RoleName: rs.Name,
		RPK:      rs.Rpk,
	}

	return r, nil
}

func (m *ModelSerializer) SerializeRoleAssignment(ra *models.RoleAssignment) (*protos.RoleAssignment, error) {

	ras := &protos.RoleAssignmentSigned{
		Version:      CurrentRoleAssignmentSignedVersion,
		RoleName:     ra.RoleName,
		UserId:       ra.UserID,
		PublicKeyId:  ra.PublicKeyID,
		EncryptedRsk: ra.EncryptedRsk,
	}

	data, err := proto.Marshal(ras)
	if err != nil {
		return nil, err
	}
	signature, err := m.GenerateSignature(data)
	if err != nil {
		return nil, err
	}

	roleAssignment := &protos.RoleAssignment{
		Version:              CurrentRoleAssignmentVersion,
		RoleAssignmentSigned: data,
		Signature:            signature,
	}
	return roleAssignment, nil
}

func (m *ModelSerializer) ParseRoleAssignment(ra *protos.RoleAssignment) (*models.RoleAssignment, error) {

	if err := m.ValidateSignature(ra.RoleAssignmentSigned, ra.Signature); err != nil {
		return nil, err
	}

	ras := &protos.RoleAssignmentSigned{}
	if err := proto.Unmarshal(ra.RoleAssignmentSigned, ras); err != nil {
		return nil, err
	}

	roleAssignment := &models.RoleAssignment{
		RoleName:     ras.RoleName,
		UserID:       ras.UserId,
		PublicKeyID:  ras.PublicKeyId,
		EncryptedRsk: ras.EncryptedRsk,
	}
	return roleAssignment, nil
}

func (m *ModelSerializer) SerializeGrantKey(key *models.GrantKey) (*protos.GrantKey, error) {

	gks := &protos.GrantKeySigned{
		Version:               CurrentGrantKeySignedVersion,
		UserId:                key.UserID,
		KeyId:                 key.KeyID,
		EncryptedGrantKeyBlob: key.EncryptedGrantKeyBlob,
		CreationDate:          key.CreationDate,
		ExpirationDate:        key.ExpirationDate,
	}

	data, err := proto.Marshal(gks)
	if err != nil {
		return nil, err
	}
	signature, err := m.GenerateSignature(data)
	if err != nil {
		return nil, err
	}

	grantKey := &protos.GrantKey{
		Version:               CurrentGrantKeyVersion,
		GrantKeySigned:        data,
		Signature:             signature,
		RecordVersion:         key.RecordVersion,
		EncryptedGrantKeyWrap: key.EncryptedGrantKeyWrap,
	}
	return grantKey, nil
}

func (m *ModelSerializer) ParseGrantKey(key *protos.GrantKey) (*models.GrantKey, error) {

	if err := m.ValidateSignature(key.GrantKeySigned, key.Signature); err != nil {
		return nil, err
	}

	gks := &protos.GrantKeySigned{}
	if err := proto.Unmarshal(key.GrantKeySigned, gks); err != nil {
		return nil, err
	}

	grantKey := &models.GrantKey{
		UserID:                gks.UserId,
		KeyID:                 gks.KeyId,
		RecordVersion:         key.RecordVersion,
		EncryptedGrantKeyWrap: key.EncryptedGrantKeyWrap,
		EncryptedGrantKeyBlob: gks.EncryptedGrantKeyBlob,
		CreationDate:          gks.CreationDate,
		ExpirationDate:        gks.ExpirationDate,
	}
	return grantKey, nil
}
