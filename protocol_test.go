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
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/passw0rd/phe-go"
)

func TestProtocol_EnrollAccount(t *testing.T) {

	require := require.New(t)

	priv := phe.GenerateClientKey()
	privStr := base64.StdEncoding.EncodeToString(priv)
	pubStr := "eyJwdWJsaWNfa2V5IjoiQkFRSlM0NHpwN2l2WG1tVlFxUjNWUnZNbmRWb09hSjFWcGRFVGRQUnB6TnozdXVqbjhnd1ZHU0JLVzVsS1FpcWFnaTU5VUVqR1YzMk9OVXZsWVg3a3kwPSIsInZlcnNpb24iOjF9"
	token1 := "eyJ1cGRhdGVfdG9rZW4iOnsiYSI6IkFTOHUxTnk1YjZjS1dPN3BuS1NoVjQrRW5SYlVFQnVKcUZmUDFzaGorUk09IiwiYiI6Im9HL0NybWJxazNxNWdLcEdkajg5bFhSUjJjZWRmdy9tUU14TVVHcFJscE09In0sInZlcnNpb24iOjJ9"
	appId := "307f21b4cdbd4de6ac88362817e6cd94"

	context, err := CreateContext(appId, privStr, pubStr)
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
	context, err = CreateContext(appId, privStr, pubStr, token1)
	require.NoError(err)
	proto, err = NewProtocol(context)
	require.NoError(err)

	newRec, err := proto.UpdateEnrollmentRecord(rec)
	require.NoError(err)

	key3, err := proto.VerifyPassword(pwd, newRec)
	require.NoError(err)
	require.Equal(key, key3)

}
