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
	"fmt"
	"sync"

	"github.com/passw0rd/phe-go"
	"github.com/pkg/errors"
)

type Protocol struct {
	AccessToken    string
	AppId          string
	PHEClients     map[uint32]*phe.Client
	UpdateTokens   map[uint32][]byte
	APIClient      *APIClient
	CurrentVersion uint32
	once           sync.Once
}

func NewProtocol(context *Context) (*Protocol, error) {

	if context == nil || context.AppId == "" || context.AccessToken == "" || context.PHEClients == nil {
		return nil, errors.New("invalid context")
	}
	return &Protocol{
		AccessToken:    context.AccessToken,
		AppId:          context.AppId,
		PHEClients:     context.PHEClients,
		UpdateTokens:   context.UpdateTokens,
		CurrentVersion: context.Version,
	}, nil
}

func (p *Protocol) EnrollAccount(password string) (enrollmentRecord []byte, encryptionKey []byte, err error) {

	req := &EnrollmentRequest{Version: p.CurrentVersion}
	resp, err := p.getClient().GetEnrollment(req)
	if err != nil {
		return nil, nil, err
	}

	pheImpl := p.getPHE(resp.Version)

	if pheImpl == nil {
		err = fmt.Errorf("unable to find keys for version %d", resp.Version)
		return
	}

	rec, key, err := pheImpl.EnrollAccount([]byte(password), resp.Response)

	if err != nil {
		return nil, nil, errors.Wrap(err, "could not enroll account")
	}

	enrollmentRecord, err = MarshalRecord(p.CurrentVersion, rec)

	if err != nil {
		return nil, nil, errors.Wrap(err, "could not serialize enrollment record")
	}

	return enrollmentRecord, key, nil

}

func (p *Protocol) VerifyPassword(password string, enrollmentRecord []byte) (key []byte, err error) {

	version, record, err := UnmarshalRecord(enrollmentRecord)

	if err != nil {
		return nil, errors.Wrap(err, "invalid record")
	}

	pheImpl := p.getPHE(version)
	if pheImpl == nil {
		return nil, errors.New("unable to find keys corresponding to this record's version")
	}

	req, err := pheImpl.CreateVerifyPasswordRequest([]byte(password), record)
	if err != nil {
		return nil, errors.Wrap(err, "could not create verify password request")
	}

	versionedReq := &VerifyPasswordRequest{
		Version: uint32(version),
		Request: req,
	}

	resp, err := p.getClient().VerifyPassword(versionedReq)
	if err != nil || resp == nil {
		return nil, errors.Wrap(err, "error while requesting service")
	}

	key, err = pheImpl.CheckResponseAndDecrypt([]byte(password), record, resp.Response)

	if err != nil {
		return nil, errors.Wrap(err, "error after requesting service")
	}

	if len(key) == 0 {
		return nil, ErrInvalidPassword
	}

	return key, nil
}

func (p *Protocol) UpdateEnrollmentRecord(oldRecord []byte) (newRecord []byte, err error) {
	version, record, err := UnmarshalRecord(oldRecord)

	if err != nil {
		return nil, errors.Wrap(err, "invalid record")
	}

	if version == p.CurrentVersion {
		return oldRecord, nil
	}

	if version > p.CurrentVersion {
		return nil, errors.New("record's version is greater than protocol's version")
	}

	var newRec []byte
	recVersion := version
	for recVersion < p.CurrentVersion {
		token := p.getToken(recVersion + 1)
		if token == nil {
			return nil, errors.New("protocol does not contain token to update record to the current version")
		}

		newRec, err = phe.UpdateRecord(record, token)
		if err != nil {
			return nil, err
		}
		recVersion++
	}

	newRecord, err = MarshalRecord(p.CurrentVersion, newRec)
	return
}

func (p *Protocol) getClient() *APIClient {
	p.once.Do(func() {
		if p.APIClient == nil {
			p.APIClient = &APIClient{
				AccessToken: p.AccessToken,
				AppID:       p.AppId,
			}
		}
	})
	return p.APIClient
}

func (p *Protocol) getPHE(version uint32) *phe.Client {

	pheImpl, ok := p.PHEClients[version]
	if !ok {
		return nil
	}

	return pheImpl
}

func (p *Protocol) getToken(version uint32) []byte {
	if p.UpdateTokens == nil || version < 1 {
		return nil
	}
	token, ok := p.UpdateTokens[uint32(version)]
	if !ok {
		return nil
	}
	return token
}

func (p *Protocol) getCurrentPHE() *phe.Client {
	return p.PHEClients[p.CurrentVersion]
}
