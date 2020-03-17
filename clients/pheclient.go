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
	"net/http"

	"github.com/VirgilSecurity/virgil-purekit-go/protos"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/common/client"
)

//PheClient implements API request layer
type PheClient struct {
	*Client
}

const (
	PheApiURL = "https://api.virgilsecurity.com/phe/v1"
)

//GetEnrollment receives random enrollment from service
func (c *PheClient) GetEnrollment(req *protos.EnrollmentRequest) (resp *protos.EnrollmentResponse, err error) {
	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: ENROLL,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}
	hresp, err := c.getClient().Send(context.TODO(), hreq)
	if err != nil {
		return nil, err
	}
	resp = &protos.EnrollmentResponse{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}

//VerifyPassword does not send password to server, only the part tat server provided in GetEnrollment
func (c *PheClient) VerifyPassword(req *protos.VerifyPasswordRequest) (resp *protos.VerifyPasswordResponse, err error) {

	hreq := &client.Request{
		Method:   http.MethodPost,
		Endpoint: VERIFY_PASSWORD,
		Header:   c.makeHeader(c.AppToken),
		Payload:  req,
	}

	hresp, err := c.getClient().Send(context.TODO(), hreq)
	if err != nil {
		return nil, err
	}
	resp = &protos.VerifyPasswordResponse{}
	if err = hresp.Unmarshal(resp); err != nil {
		return nil, err
	}
	return
}
