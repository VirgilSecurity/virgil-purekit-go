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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtocol_EnrollAccount(t *testing.T) {

	req := require.New(t)

	accessToken := os.Getenv("ACCESS_TOKEN")

	if accessToken == "" {
		t.Skip("no parameters")
	}

	skStr := os.Getenv("SECRET_KEY")

	pubStr := os.Getenv("PUBLIC_KEY")
	token1 := os.Getenv("UPDATE_TOKEN")
	address := os.Getenv("SERVER_ADDRESS")

	context, err := CreateContext(accessToken, skStr, pubStr, "")
	req.NoError(err)

	proto, err := NewProtocol(context)
	req.NoError(err)

	if address != "" {
		proto.APIClient = &APIClient{
			AccessToken: accessToken,
			URL:         address,
		}
	}

	const pwd = "p@ssw0Rd"
	rec, key, err := proto.EnrollAccount(pwd)
	req.NoError(err)
	req.True(len(rec) > 0)
	req.True(len(key) == 32)

	key1, err := proto.VerifyPassword(pwd, rec)
	req.NoError(err)
	req.Equal(key, key1)

	key2, err := proto.VerifyPassword("p@ss", rec)
	req.EqualError(err, ErrInvalidPassword.Error())
	req.Nil(key2)

	//rotate happened
	context, err = CreateContext(accessToken, skStr, pubStr, token1)
	req.NoError(err)
	proto, err = NewProtocol(context)
	req.NoError(err)

	if address != "" {
		proto.APIClient = &APIClient{
			AccessToken: accessToken,
			URL:         address,
		}
	}

	newRec, err := proto.UpdateEnrollmentRecord(rec)
	req.NoError(err)

	key3, err := proto.VerifyPassword(pwd, newRec)
	req.NoError(err)
	req.Equal(key, key3)

}
