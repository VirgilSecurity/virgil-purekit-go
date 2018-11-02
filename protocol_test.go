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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtocol_EnrollAccount(t *testing.T) {

	require := require.New(t)

	accessToken := "OSoPhirdopvijQl-FPKdlSydN9BUrn5oEuDwf3-Hqps="
	privStr := "SK.1.xacDjofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
	pubStr := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="
	token1 := "UT.2.MEQEILA6+pWr7ua7XnQIydKAgM9FIg4Dy4x7vNcJq6EwI44dBCBGKk3TVbG43txnHxVk6Be+rI5z+9ciIDCBFXCpUpkomA=="
	appId := "c7717707d03f4d3589804e7509e5d7d7"

	context, err := CreateContext(accessToken, appId, privStr, pubStr)
	require.NoError(err)

	proto, err := NewProtocol(context)
	require.NoError(err)

	const pwd = "p@ssw0Rd"
	rec, key, err := proto.EnrollAccount(pwd)
	require.NoError(err)
	require.True(len(rec) > 0)
	require.True(len(key) == 32)

	key1, err := proto.VerifyPassword(pwd, rec)
	require.NoError(err)
	require.Equal(key, key1)

	key2, err := proto.VerifyPassword("p@ss", rec)
	require.EqualError(err, ErrInvalidPassword.Error())
	require.Nil(key2)

	//rotate happened
	context, err = CreateContext(accessToken, appId, privStr, pubStr, token1)
	require.NoError(err)
	proto, err = NewProtocol(context)
	require.NoError(err)

	newRec, err := proto.UpdateEnrollmentRecord(rec)
	require.NoError(err)

	key3, err := proto.VerifyPassword(pwd, newRec)
	require.NoError(err)
	require.Equal(key, key3)

}
