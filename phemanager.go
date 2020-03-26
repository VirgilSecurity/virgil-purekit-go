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
	"fmt"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/models"

	"github.com/pkg/errors"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/clients"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"
)

type PheManager struct {
	Crypto         *crypto.Crypto
	CurrentVersion uint32
	UpdateToken    []byte
	CurrentClient  *phe.PheClient
	PreviousClient *phe.PheClient
	HttpClient     *clients.PheClient
}

func NewPheManager(context *Context) (*PheManager, error) {
	mgr := &PheManager{}
	mgr.Crypto = context.Crypto
	currentClient := phe.NewPheClient()
	currentClient.SetRandom(random)
	currentClient.SetOperationRandom(random)
	mgr.CurrentClient = currentClient
	if context.UpdateToken != nil {
		mgr.CurrentVersion = context.PublicKey.Version + 1
		mgr.UpdateToken = context.UpdateToken.Payload1
		prevClient := phe.NewPheClient()
		mgr.PreviousClient = prevClient
		prevClient.SetRandom(random)
		prevClient.SetOperationRandom(random)
		if err := prevClient.SetKeys(context.SecretKey.Payload1, context.PublicKey.Payload1); err != nil {
			return nil, err
		}
		newPriv, newPub, err := prevClient.RotateKeys(mgr.UpdateToken)
		if err != nil {
			return nil, err
		}
		if err = currentClient.SetKeys(newPriv, newPub); err != nil {
			return nil, err
		}
	} else {
		mgr.CurrentVersion = context.PublicKey.Version
		if err := currentClient.SetKeys(context.SecretKey.Payload1, context.PublicKey.Payload1); err != nil {
			return nil, err
		}
	}
	mgr.HttpClient = context.PheClient
	return mgr, nil
}

func (p *PheManager) GetPheClient(pheVersion uint32) (*phe.PheClient, error) {
	if pheVersion == p.CurrentVersion {
		return p.CurrentClient, nil
	} else if p.CurrentVersion == pheVersion+1 && p.PreviousClient != nil {
		return p.PreviousClient, nil
	}
	return nil, fmt.Errorf("no client with phe version %d", pheVersion)
}

func (p *PheManager) GetEnrollment(passwordHash []byte) (record, key []byte, err error) {
	req := &protos.EnrollmentRequest{Version: p.CurrentVersion}
	resp, err := p.HttpClient.GetEnrollment(req)
	if err != nil {
		return nil, nil, err
	}
	return p.CurrentClient.EnrollAccount(resp.Response, passwordHash)
}

func (p *PheManager) ComputePheKey(record *models.UserRecord, passwordHash []byte) (key []byte, err error) {

	pheImpl, err := p.GetPheClient(record.RecordVersion)
	if err != nil || pheImpl == nil {
		return nil, errors.New("no phe implementations corresponding to this record's version")
	}

	req, err := pheImpl.CreateVerifyPasswordRequest(passwordHash, record.PheRecord)
	if err != nil {
		return nil, errors.Wrap(err, "could not create verify password request")
	}

	versionedReq := &protos.VerifyPasswordRequest{
		Version: record.RecordVersion,
		Request: req,
	}

	resp, err := p.HttpClient.VerifyPassword(versionedReq)
	if err != nil || resp == nil {
		return nil, errors.Wrap(err, "error while requesting PHE service")
	}

	key, err = pheImpl.CheckResponseAndDecrypt(passwordHash, record.PheRecord, resp.Response)

	if err != nil {
		return nil, errors.Wrap(err, "error after requesting service")
	}
	if len(key) == 0 {
		return nil, ErrInvalidPassword
	}
	return key, nil
}

func (p *PheManager) PerformRotation(record []byte) ([]byte, error) {
	if p.PreviousClient == nil {
		return nil, errors.New("nothing to rotate with")
	}
	return p.PreviousClient.UpdateEnrollmentRecord(record, p.UpdateToken)
}
