/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

package passw0rd

import (
	"net/http"
	"path"
	"sync"

	"github.com/passw0rd/sdk-go/common"
)

type APIClient struct {
	AccessToken string
	AppID       string
	URL         string
	HTTPClient  *common.VirgilHTTPClient
	once        sync.Once
}

func (c *APIClient) GetEnrollment(req *EnrollmentRequest) (resp *EnrollmentResponse, err error) {
	resp = &EnrollmentResponse{}
	_, err = c.getClient().Send(c.AccessToken, http.MethodPost, path.Join(c.AppID, "enroll"), req, resp)
	return
}

func (c *APIClient) VerifyPassword(req *VerifyPasswordRequest) (resp *VerifyPasswordResponse, err error) {
	resp = &VerifyPasswordResponse{}
	_, err = c.getClient().Send(c.AccessToken, http.MethodPost, path.Join(c.AppID, "verify-password"), req, resp)
	return
}

func (c *APIClient) getClient() *common.VirgilHTTPClient {
	c.once.Do(func() {
		if c.HTTPClient == nil {
			c.HTTPClient = &common.VirgilHTTPClient{
				Address: c.getUrl(),
			}
		}
	})
	return c.HTTPClient
}

func (c *APIClient) getUrl() string {
	if c.URL != "" {
		return c.URL
	}
	return "https://api.passw0rd.io/phe/v1"
}
