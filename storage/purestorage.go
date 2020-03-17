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
	"github.com/VirgilSecurity/virgil-purekit-go/models"
)

type PureStorage interface {
	InsertUser(record *models.UserRecord) error
	UpdateUser(record *models.UserRecord) error
	UpdateUsers(records []*models.UserRecord, previousRecordVersion int) error
	SelectUser(userId string) (*models.UserRecord, error)
	SelectUsers(userIds ...string) ([]*models.UserRecord, error)
	DeleteUser(userId string, cascade bool) error
	SelectCellKey(userId, dataId string) (*models.CellKey, error)
	InsertCellKey(key *models.CellKey) error
	UpdateCellKey(key *models.CellKey) error
	DeleteCellKey(userId, dataId string) error
	InsertRole(role *models.Role) error
	SelectRoles(roleNames ...string) ([]*models.Role, error)
	InsertRoleAssignments(assignments ...*models.RoleAssignment) error
	SelectRoleAssignments(userId string) ([]*models.RoleAssignment, error)
	SelectRoleAssignment(roleName, userId string) (*models.RoleAssignment, error)
	DeleteRoleAssignments(roleName string, userIds ...string) error
	InsertGrantKey(key *models.GrantKey) error
	SelectGrantKey(userId string, keyId []byte) (*models.GrantKey, error)
	SelectGrantKeys(recordVersion int) (*models.GrantKey, error)
	UpdateGrantKeys(keys ...*models.GrantKey) error
	DeleteGrantKey(userId string, keyId []byte) error
}

type SerializerDependentStorage interface {
	SetSerializer(serializer *ModelSerializer)
}
