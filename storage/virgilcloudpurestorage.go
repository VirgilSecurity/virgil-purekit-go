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
	"bytes"
	"errors"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/clients"
	"github.com/VirgilSecurity/virgil-purekit-go/v3/models"
	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"
)

type VirgilCloudPureStorage struct {
	Serializer *ModelSerializer
	Client     *clients.PureClient
}

func (v *VirgilCloudPureStorage) SetSerializer(serializer *ModelSerializer) {
	v.Serializer = serializer
}

func (v *VirgilCloudPureStorage) InsertUser(record *models.UserRecord) error {
	return v.sendUser(record, true)
}

func (v *VirgilCloudPureStorage) UpdateUser(record *models.UserRecord) error {
	return v.sendUser(record, false)
}

func (v *VirgilCloudPureStorage) UpdateUsers(records []*models.UserRecord, previousRecordVersion uint32) error {
	return errors.New("this method always throws UnsupportedOperationException, as in case of using " +
		"Virgil Cloud storage, rotation happens on the Virgil side")
}

func (v *VirgilCloudPureStorage) SelectUser(userID string) (*models.UserRecord, error) {

	rec, err := v.Client.GetUser(&protos.UserIdRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	mRec, err := v.Serializer.ParseUserRecord(rec)
	if err != nil {
		return nil, err
	}
	if mRec.UserID != userID {
		return nil, errors.New("user id mismatch")
	}
	return mRec, nil
}

func (v *VirgilCloudPureStorage) SelectUsers(userIDs ...string) ([]*models.UserRecord, error) {

	if len(userIDs) == 0 {
		return []*models.UserRecord{}, nil
	}

	users, err := v.Client.GetUsers(userIDs...)
	if err != nil {
		return nil, err
	}

	if len(users.UserRecords) != len(userIDs) {
		return nil, errors.New("records and ids number mismatch")
	}

	recs := make([]*models.UserRecord, 0, len(userIDs))
	for _, r := range users.UserRecords {
		rec, err := v.Serializer.ParseUserRecord(r)
		if err != nil {
			return nil, err
		}
		if !contains(userIDs, rec.UserID) {
			return nil, errors.New("userID mismatch")
		}
		recs = append(recs, rec)
	}
	return recs, nil
}
func (v *VirgilCloudPureStorage) SelectUsersByVersion(version uint32) ([]*models.UserRecord, error) {
	return nil, errors.New("this method always throws UnsupportedOperationException, as in case of using " +
		"Virgil Cloud storage, rotation happens on the Virgil side")
}

func (v *VirgilCloudPureStorage) DeleteUser(userID string, cascade bool) error {
	return v.Client.DeleteUser(&protos.UserIdRequest{UserId: userID}, cascade)
}

func (v *VirgilCloudPureStorage) SelectCellKey(userID, dataID string) (*models.CellKey, error) {
	key, err := v.Client.GetCellKey(&protos.UserIdAndDataIdRequest{
		UserId: userID,
		DataId: dataID,
	})
	if err != nil {
		var httpErr *protos.HttpError
		if errors.As(err, &httpErr) && httpErr.Code == 50004 {
			return nil, ErrorNotFound
		}
		return nil, err
	}
	mKey, err := v.Serializer.ParseCellKey(key)
	if err != nil {
		return nil, err
	}
	if mKey.UserID != userID || mKey.DataID != dataID {
		return nil, errors.New("cell key id or user id mismatch")
	}
	return mKey, nil
}

func (v *VirgilCloudPureStorage) InsertCellKey(key *models.CellKey) error {
	return v.insertKey(key, true)
}

func (v *VirgilCloudPureStorage) UpdateCellKey(key *models.CellKey) error {
	return v.insertKey(key, false)
}

func (v *VirgilCloudPureStorage) DeleteCellKey(userID, dataID string) error {
	return v.Client.DeleteCellKey(&protos.UserIdAndDataIdRequest{
		UserId: userID,
		DataId: dataID,
	})
}

func (v *VirgilCloudPureStorage) InsertRole(role *models.Role) error {

	r, err := v.Serializer.SerializeRole(role)
	if err != nil {
		return err
	}
	return v.Client.InsertRole(r)
}

func (v *VirgilCloudPureStorage) SelectRoles(roleNames ...string) ([]*models.Role, error) {
	if len(roleNames) == 0 {
		return []*models.Role{}, nil
	}

	rolesRequest := &protos.GetRoles{RoleNames: roleNames}

	roles, err := v.Client.GetRoles(rolesRequest)
	if err != nil {
		return nil, err
	}
	if len(roles.Roles) != len(roleNames) {
		return nil, errors.New("role ids and returned roles number mismatch")
	}

	mdls := make([]*models.Role, 0, len(roleNames))
	for _, r := range roles.Roles {
		role, err := v.Serializer.ParseRole(r)
		if err != nil {
			return nil, err
		}
		if !contains(roleNames, role.RoleName) {
			return nil, errors.New("role name mismatch")
		}
		mdls = append(mdls, role)
	}
	return mdls, nil
}

func (v *VirgilCloudPureStorage) InsertRoleAssignments(assignments ...*models.RoleAssignment) error {

	if len(assignments) == 0 {
		return nil
	}

	req := &protos.RoleAssignments{}
	for _, r := range assignments {
		ra, err := v.Serializer.SerializeRoleAssignment(r)
		if err != nil {
			return err
		}
		req.RoleAssignments = append(req.RoleAssignments, ra)
	}
	return v.Client.InsertRoleAssignments(req)
}

func (v *VirgilCloudPureStorage) SelectRoleAssignments(userID string) ([]*models.RoleAssignment, error) {

	req := &protos.GetRoleAssignments{UserId: userID}

	ras, err := v.Client.GetRoleAssignments(req)
	if err != nil {
		return nil, err
	}
	mdls := make([]*models.RoleAssignment, 0, len(ras.RoleAssignments))
	for _, ra := range ras.RoleAssignments {
		model, err := v.Serializer.ParseRoleAssignment(ra)
		if err != nil {
			return nil, err
		}
		if model.UserID != userID {
			return nil, errors.New("user ID mismatch")
		}
		mdls = append(mdls, model)
	}
	return mdls, nil
}

func (v *VirgilCloudPureStorage) SelectRoleAssignment(roleName, userID string) (*models.RoleAssignment, error) {

	req := &protos.GetRoleAssignment{
		UserId:   userID,
		RoleName: roleName,
	}

	ra, err := v.Client.GetRoleAssignment(req)
	if err != nil {
		return nil, err
	}

	mra, err := v.Serializer.ParseRoleAssignment(ra)
	if err != nil {
		return nil, err
	}
	if mra.RoleName != roleName || mra.UserID != userID {
		return nil, errors.New("role name or user id mismatch")
	}
	return mra, nil
}

func (v *VirgilCloudPureStorage) DeleteRoleAssignments(roleName string, userIDs ...string) error {

	if len(userIDs) == 0 {
		return nil
	}
	req := &protos.DeleteRoleAssignments{
		RoleName: roleName,
		UserIds:  userIDs,
	}
	return v.Client.DeleteRoleAssignments(req)
}

func (v *VirgilCloudPureStorage) InsertGrantKey(key *models.GrantKey) error {

	req, err := v.Serializer.SerializeGrantKey(key)
	if err != nil {
		return err
	}
	return v.Client.InsertGrantKey(req)
}

func (v *VirgilCloudPureStorage) SelectGrantKey(userID string, keyID []byte) (*models.GrantKey, error) {

	req := &protos.GrantKeyDescriptor{
		UserId: userID,
		KeyId:  keyID,
	}

	gk, err := v.Client.GetGrantKey(req)
	if err != nil {
		return nil, err
	}

	mgk, err := v.Serializer.ParseGrantKey(gk)
	if err != nil {
		return nil, err
	}
	if mgk.UserID != userID || !bytes.Equal(mgk.KeyID, keyID) {
		return nil, errors.New("user id or key id mismatch")
	}
	return mgk, nil
}

func (v *VirgilCloudPureStorage) SelectGrantKeys(recordVersion uint32) ([]*models.GrantKey, error) {
	return nil, errors.New("this method always throws UnsupportedOperationException, as in case of using " +
		"Virgil Cloud storage, rotation happens on the Virgil side")
}

func (v *VirgilCloudPureStorage) UpdateGrantKeys(keys ...*models.GrantKey) error {
	return errors.New("this method always throws UnsupportedOperationException, as in case of using " +
		"Virgil Cloud storage, rotation happens on the Virgil side")
}

func (v *VirgilCloudPureStorage) DeleteGrantKey(userID string, keyID []byte) error {

	req := &protos.GrantKeyDescriptor{
		UserId: userID,
		KeyId:  keyID,
	}
	return v.Client.DeleteGrantKey(req)
}

func (v *VirgilCloudPureStorage) sendUser(user *models.UserRecord, insert bool) error {
	userModel, err := v.Serializer.SerializeUserRecord(user)
	if err != nil {
		return err
	}

	if insert {
		err = v.Client.InsertUser(userModel)
	} else {
		err = v.Client.UpdateUser(userModel)
	}
	return err
}

func (v *VirgilCloudPureStorage) insertKey(key *models.CellKey, insert bool) error {
	ck, err := v.Serializer.SerializeCellKey(key)
	if err != nil {
		return err
	}
	if insert {
		err = v.Client.InsertCellKey(ck)
		if err != nil {
			var httpErr *protos.HttpError
			if errors.As(err, &httpErr) && httpErr.Code == 50006 {
				return ErrorAlreadyExists
			}
		}
		return err
	}
	return v.Client.UpdateCellKey(ck)
}

func contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}
