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

package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type VirgilHTTPClient struct {
	Client  HTTPClient
	Address string
	once    sync.Once
}

func (vc *VirgilHTTPClient) Send(token string, method string, urlPath string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(err, "VirgilHTTPClient.Send: marshal payload")
		}
	}

	u, err := url.Parse(vc.Address)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: URL parse")
	}

	u.Path = path.Join(u.Path, urlPath)
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: new request")
	}

	if token != "" {
		req.Header.Add("Authorization", token)
	}

	client := vc.getHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: send request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("not found")
	}

	if resp.StatusCode == http.StatusOK {
		if respObj != nil {

			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(respObj)
			if err != nil {
				return nil, errors.Wrap(err, "VirgilHTTPClient.Send: unmarshal response object")
			}
		}
		return resp.Header, nil
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: read response body")
	}

	return nil, fmt.Errorf("%d %s", resp.StatusCode, string(respBody))
}

func (vc *VirgilHTTPClient) getHTTPClient() HTTPClient {

	vc.once.Do(func() {

		if vc.Client == nil {

			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
				DualStack: true,
			}

			var netTransport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				TLSHandshakeTimeout: 10 * time.Second,
			}
			var cli = &http.Client{
				Timeout:   10 * time.Second,
				Transport: netTransport,
			}

			vc.Client = cli
		}
	})

	return vc.Client
}
