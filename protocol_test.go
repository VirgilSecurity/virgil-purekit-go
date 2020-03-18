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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
)

func BuildContext() (ctx *Context, buppk crypto.PrivateKey, nmsData []byte, err error) {
	c := &crypto.Crypto{}
	nmsData, _ = c.Random(32)
	nms := fmt.Sprintf("NM.%s", base64.StdEncoding.EncodeToString(nmsData))

	buppk, _ = c.GenerateKeypair()
	bubin, _ := c.ExportPublicKey(buppk.PublicKey())
	bup := fmt.Sprintf("BU.%s", base64.StdEncoding.EncodeToString(bubin))

	at := os.Getenv("TEST_APP_TOKEN")
	sk1 := os.Getenv("TEST_SK1")
	pk1 := os.Getenv("TEST_PK1")
	pheUrl := os.Getenv("TEST_PHE_URL")
	pureUrl := os.Getenv("TEST_PURE_URL")
	kmsUrl := os.Getenv("TEST_KMS_URL")

	ctx, err = CreateCloudContext(at, nms, bup, sk1, pk1, nil, pheUrl, pureUrl, kmsUrl)

	/*ctx.Storage.(*storage.VirgilCloudPureStorage).Client.HTTPClient =
	client.NewClient(ctx.Storage.(*storage.VirgilCloudPureStorage).Client.URL,
		client.VirgilProduct("PureKit", "v3.0.0"),
		client.DefaultCodec(&clients.ProtobufCodec{}),
		client.ErrorHandler(clients.DefaultErrorHandler),
		client.HTTPClient(&http.Client{
			Transport: &DebugClient{Transport: http.DefaultTransport},
		}))*/
	return
}

func TestPure_RegisterUser_AuthenticateUser(t *testing.T) {
	userName := randomString()
	password := randomString()

	ctx, _, _, err := BuildContext()
	require.NoError(t, err)

	p, err := NewPure(ctx)
	require.NoError(t, err)

	err = p.RegisterUser(userName, password)
	require.NoError(t, err)

	res, err := p.AuthenticateUser(userName, password, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestPure_EncryptDecrypt(t *testing.T) {
	userName := randomString()
	password := randomString()
	dataId := randomString()
	plaintext := randomString()

	ctx, _, _, err := BuildContext()
	require.NoError(t, err)

	p, err := NewPure(ctx)
	require.NoError(t, err)

	err = p.RegisterUser(userName, password)
	require.NoError(t, err)

	res, err := p.AuthenticateUser(userName, password, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	ciphertext, err := p.encrypt(userName, dataId, nil, nil, nil, []byte(plaintext))
	require.NoError(t, err)
	decrypted, err := p.Decrypt(res.Grant, userName, dataId, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted))
}

func TestPure_EncryptDecrypt_Share_Unshare_Admin_ChangePassword(t *testing.T) {
	userId1 := randomString()
	password1 := randomString()
	userId2 := randomString()
	password2 := randomString()
	dataId := randomString()
	plaintext := randomString()
	password3 := randomString()

	ctx, buppk, _, err := BuildContext()
	require.NoError(t, err)

	p, err := NewPure(ctx)
	require.NoError(t, err)

	err = p.RegisterUser(userId1, password1)
	require.NoError(t, err)

	res1, err := p.AuthenticateUser(userId1, password1, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	require.NotNil(t, res1)

	err = p.RegisterUser(userId2, password2)
	require.NoError(t, err)

	res2, err := p.AuthenticateUser(userId2, password2, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	require.NotNil(t, res2)

	ciphertext, err := p.encrypt(userId1, dataId, nil, nil, nil, []byte(plaintext))
	require.NoError(t, err)

	err = p.Share(res1.Grant, dataId, []string{userId2}, nil)
	require.NoError(t, err)
	decrypted1, err := p.Decrypt(res1.Grant, "", dataId, ciphertext)
	require.NoError(t, err)
	decrypted2, err := p.Decrypt(res2.Grant, userId1, dataId, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted1))
	require.Equal(t, plaintext, string(decrypted2))

	//test Unshare
	err = p.Unshare(userId1, dataId, []string{userId2}, nil)
	require.NoError(t, err)

	decrypted2, err = p.Decrypt(res2.Grant, userId1, dataId, ciphertext)
	require.Error(t, err)
	require.Nil(t, decrypted2)

	//test Admin
	adminGrant, err := p.CreateUserGrantAsAdmin(userId1, buppk, DEFAULT_GRANT_TTL)
	require.NoError(t, err)
	require.NotNil(t, adminGrant)
	decryptedAdmin, err := p.Decrypt(adminGrant, "", dataId, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decryptedAdmin))

	err = p.ChangeUserPasswordWithGrant(adminGrant, password3)
	require.NoError(t, err)

	res3, err := p.AuthenticateUser(userId1, password3, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)

	decrypted3, err := p.Decrypt(res3.Grant, "", dataId, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted3))
}

func TestPure_Roles(t *testing.T) {
	userId1 := randomString()
	userId2 := randomString()
	userId3 := randomString()
	password1 := randomString()
	password2 := randomString()
	password3 := randomString()
	dataId := randomString()
	plaintext := randomString()
	roleName := randomString()

	ctx, _, _, err := BuildContext()
	require.NoError(t, err)

	p, err := NewPure(ctx)
	require.NoError(t, err)

	err = p.RegisterUser(userId1, password1)
	require.NoError(t, err)
	err = p.RegisterUser(userId2, password2)
	require.NoError(t, err)
	err = p.RegisterUser(userId3, password3)
	require.NoError(t, err)

	//create role for users 1 and 2
	err = p.CreateRole(roleName, []string{userId1, userId2}...)
	require.NoError(t, err)

	res1, err := p.AuthenticateUser(userId1, password1, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	res2, err := p.AuthenticateUser(userId2, password2, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)
	res3, err := p.AuthenticateUser(userId3, password3, &SessionParameters{
		SessionID: randomString(),
		TTL:       DEFAULT_GRANT_TTL,
	})
	require.NoError(t, err)

	//user1 encrypts to role
	ciphertext, err := p.encrypt(userId1, dataId, nil, []string{roleName}, nil, []byte(plaintext))
	require.NoError(t, err)

	decrypted1, err := p.Decrypt(res1.Grant, "", dataId, ciphertext)
	require.NoError(t, err)
	decrypted2, err := p.Decrypt(res2.Grant, userId1, dataId, ciphertext)
	require.NoError(t, err)

	require.Equal(t, plaintext, string(decrypted1))
	require.Equal(t, plaintext, string(decrypted2))

	//third user decryption should fail
	decrypted3, err := p.Decrypt(res3.Grant, "", dataId, ciphertext)
	require.Error(t, err)
	require.Nil(t, decrypted3)

	//assign role to user3
	err = p.AssignRoleWithGrant(roleName, res2.Grant, []string{userId3}...)
	require.NoError(t, err)
	//remove role from user1,2
	err = p.UnassignRole(roleName, []string{userId1, userId2}...)
	require.NoError(t, err)

	//user1 should decrypt because he's owner
	decrypted1, err = p.Decrypt(res1.Grant, "", dataId, ciphertext)
	require.NoError(t, err)
	//user3 should decrypt because he's in role
	decrypted3, err = p.Decrypt(res3.Grant, userId1, dataId, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted1))
	require.Equal(t, plaintext, string(decrypted3))

	//user2 no longer has access
	decrypted2, err = p.Decrypt(res2.Grant, userId1, dataId, ciphertext)
	require.Error(t, err)
	require.Nil(t, decrypted2)

	//user3 assigns role to user2
	err = p.AssignRoleWithGrant(roleName, res3.Grant, []string{userId2}...)
	require.NoError(t, err)

	//user2 should now be able to decrypt
	decrypted2, err = p.Decrypt(res2.Grant, userId1, dataId, ciphertext)
	require.NoError(t, err)

	require.Equal(t, plaintext, string(decrypted2))

}

func randomString() string {
	b := make([]byte, 8)
	rand.Read(b)
	t := base64.StdEncoding.EncodeToString(b)
	return t
}

type DebugClient struct {
	Transport http.RoundTripper
}

func (c *DebugClient) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		body []byte
		err  error
	)
	fmt.Println("Request:", req.Method, req.URL.String())

	if len(req.Header) > 0 {
		fmt.Println("Header:")
		for key := range req.Header {
			fmt.Println("\t", key, ":", req.Header.Get(key))
		}
		fmt.Println("")
	}
	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("cannot read body request: %v", err)
		}
		fmt.Println("Body:", base64.StdEncoding.EncodeToString(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	resp, err := c.Transport.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	fmt.Println("Response:", resp.StatusCode)
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot read body request: %v", err)
	}
	fmt.Println("Body:", base64.StdEncoding.EncodeToString(body))
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))

	fmt.Println("")
	return resp, nil
}
