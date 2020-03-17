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

package clients

import (
	"context"
	"fmt"
	"net/http"

	"github.com/VirgilSecurity/virgil-purekit-go/protos"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/common/client"
)

//PureClient implements API request layer
type PureClient struct {
	*Client
}

const (
	PureApiURL = "https://api.virgilsecurity.com/pure/v1"
)

const keyCascade = "cascade"

//InsertUser
func (c *PureClient) InsertUser(req *protos.UserRecord) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: INSERT_USER,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) UpdateUser(req *protos.UserRecord) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: UPDATE_USER,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) GetUser(req *protos.UserIdRequest) (resp *protos.UserRecord, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_USER,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	hresp, err := c.getClient().Send(context.TODO(), hreq)

	if err != nil {
		return nil, err
	}
	resp = &protos.UserRecord{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

func (c *PureClient) GetUsers(userIds ...string) (resp *protos.UserRecords, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_USERS,
		Header:   c.makeHeader(c.AppToken),
	}

	req := &protos.GetUserRecords{UserIds: userIds}
	hreq.Payload = req
	hresp, err := c.getClient().Send(context.TODO(), hreq)

	if err != nil {
		return nil, err
	}
	resp = &protos.UserRecords{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

func (c *PureClient) DeleteUser(req *protos.UserIdRequest, cascade bool) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: DELETE_USER,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	hreq.Endpoint += fmt.Sprintf("?%s=%t", keyCascade, cascade)
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) InsertCellKey(req *protos.CellKey) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: INSERT_CELL_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) UpdateCellKey(req *protos.CellKey) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: UPDATE_CELL_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) GetCellKey(req *protos.UserIdAndDataIdRequest) (resp *protos.CellKey, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_CELL_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	hresp, err := c.getClient().Send(context.TODO(), hreq)

	if err != nil {
		return nil, err
	}
	resp = &protos.CellKey{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

func (c *PureClient) DeleteCellKey(req *protos.UserIdAndDataIdRequest) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: DELETE_CELL_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) InsertRole(req *protos.Role) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: INSERT_ROLE,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) GetRoles(req *protos.GetRoles) (resp *protos.Roles, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_ROLES,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}

	hresp, err := c.getClient().Send(context.TODO(), hreq)

	if err != nil {
		return nil, err
	}
	resp = &protos.Roles{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

func (c *PureClient) InsertRoleAssignments(req *protos.RoleAssignments) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: INSERT_ROLE_ASSIGNMENTS,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) GetRoleAssignments(req *protos.GetRoleAssignments) (resp *protos.RoleAssignments, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_ROLE_ASSIGNMENTS,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}

	if hresp, err := c.getClient().Send(context.TODO(), hreq); err != nil {
		return nil, err
	} else {
		resp = &protos.RoleAssignments{}
		if err = hresp.Unmarshal(resp); err != nil {
			return nil, err
		}
	}
	return
}

func (c *PureClient) GetRoleAssignment(req *protos.GetRoleAssignment) (resp *protos.RoleAssignment, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_ROLE_ASSIGNMENT,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}

	if hresp, err := c.getClient().Send(context.TODO(), hreq); err != nil {
		return nil, err
	} else {
		resp = &protos.RoleAssignment{}
		if err = hresp.Unmarshal(resp); err != nil {
			return nil, err
		}
	}
	return
}

func (c *PureClient) DeleteRoleAssignments(req *protos.DeleteRoleAssignments) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: DELETE_ROLE_ASSIGNMENTS,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) InsertGrantKey(req *protos.GrantKey) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: INSERT_GRANT_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}

func (c *PureClient) GetGrantKey(req *protos.GrantKeyDescriptor) (resp *protos.GrantKey, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: GET_GRANT_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	hresp, err := c.getClient().Send(context.TODO(), hreq)

	if err != nil {
		return nil, err
	}
	resp = &protos.GrantKey{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

func (c *PureClient) DeleteGrantKey(req *protos.GrantKeyDescriptor) (err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: DELETE_GRANT_KEY,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	_, err = c.getClient().Send(context.TODO(), hreq)
	return err
}
