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
	"net/http"
	"sync"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/common/client"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
)

type Client struct {
	AppToken   string
	URL        string
	HTTPClient *client.Client
	once       sync.Once
}

func (c *Client) getClient() *client.Client {
	c.once.Do(func() {
		if c.HTTPClient == nil {
			c.HTTPClient = client.NewClient(c.URL,
				client.VirgilProduct("PureKit", "v3.0.1"),
				client.DefaultCodec(&ProtobufCodec{}),
				client.ErrorHandler(DefaultErrorHandler),
			)
		}
	})
	return c.HTTPClient
}

func (c *Client) makeHeader(token string) http.Header {
	return http.Header{
		"AppToken": []string{token},
	}
}

func DefaultErrorHandler(resp *client.Response) error {
	if len(resp.Body) == 0 {
		if resp.StatusCode == http.StatusNotFound {
			return errors.ErrEntityNotFound
		}
		if resp.StatusCode/100 == 5 { // 5xx
			return errors.ErrInternalServerError
		}
	}

	apiErr := &protos.HttpError{}
	if len(resp.Body) != 0 {
		if err := resp.Unmarshal(apiErr); err != nil {
			return &client.Error{
				StatusCode: resp.StatusCode,
				Message:    string(resp.Body),
			}
		}
	}
	return apiErr
}
