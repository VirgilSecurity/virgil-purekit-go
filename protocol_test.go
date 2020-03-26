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
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/protos"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/phe"

	"github.com/VirgilSecurity/virgil-purekit-go/v3/storage"

	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
)

var envs = []string{"dev", "stg", "pro"}

func strg2str(useLocal bool) string {
	if useLocal {
		return "local"
	}
	return "cloud"
}

func GetEnv() (res map[string]map[string]string) {
	file, _ := ioutil.ReadFile("testdata/env.json")
	json.Unmarshal(file, &res)
	return
}

func BuildContext(useUpdateToken, useNewKeys, useLocalStorage, skipClean bool,
	nmsBin []byte, bpk crypto.PrivateKey, envName string) (ctx *Context, buppk crypto.PrivateKey, nmsData []byte, err error) {
	c := &crypto.Crypto{}

	if nmsBin == nil {
		nmsData, _ = c.Random(32)
	} else {
		nmsData = nmsBin
	}
	nms := fmt.Sprintf("NM.%s", base64.StdEncoding.EncodeToString(nmsData))

	if bpk == nil {
		buppk, _ = c.GenerateKeypair()
	} else {
		buppk = bpk
	}

	bubin, _ := c.ExportPublicKey(buppk.PublicKey())
	bup := fmt.Sprintf("BU.%s", base64.StdEncoding.EncodeToString(bubin))

	env := GetEnv()[envName]

	at := env["APP_TOKEN"]
	sk1 := env["SECRET_KEY_OLD"]
	pk1 := env["PUBLIC_KEY_OLD"]
	updateToken := env["UPDATE_TOKEN"]
	sk2 := env["SECRET_KEY_NEW"]
	pk2 := env["PUBLIC_KEY_NEW"]
	pheUrl := env["PHE_SERVER_ADDRESS"]
	pureUrl := env["PURE_SERVER_ADDRESS"]
	kmsUrl := env["KMS_SERVER_ADDRESS"]

	var sk, pk string

	if useNewKeys {
		sk, pk = sk2, pk2
	} else {
		sk, pk = sk1, pk1
	}

	if useLocalStorage {
		var strg storage.PureStorage
		strg, err = storage.NewMariaDBPureStorage("root:@tcp(127.0.0.1:3306)/puretest")
		if err != nil {
			return
		}
		if !skipClean {
			if err = strg.(*storage.MariaDBPureStorage).CleanDB(); err != nil {
				return
			}
			if err = strg.(*storage.MariaDBPureStorage).InitDB(60); err != nil {
				return
			}
		}

		ctx, err = CreateContext(&crypto.Crypto{}, at, nms, bup, sk, pk, strg, nil, pheUrl, kmsUrl)
	} else {
		ctx, err = CreateCloudContext(at, nms, bup, sk, pk, nil, pheUrl, pureUrl, kmsUrl)
	}

	if err == nil && useUpdateToken {
		ctx.SetUpdateToken(updateToken)
	}

	/*ctx.Storage.(*storage.VirgilCloudPureStorage).Client.HTTPClient =
	client.NewClient(ctx.Storage.(*storage.VirgilCloudPureStorage).Client.URL,
		client.VirgilProduct("PureKit", "v3.0.0"),
		client.DefaultCodec(&clients.ProtobufCodec{}),
		client.ErrorHandler(clients.DefaultErrorHandler),
		client.HTTPClient(&http.Client{
			Transport: &DebugClient{Transport: http.DefaultTransport},
		}))*/
	return ctx, buppk, nmsData, err
}

func TestPure_RegisterUser_AuthenticateUser(t *testing.T) {
	userName := randomString()
	password := randomString()
	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)

				p, err := NewPure(ctx)
				require.NoError(t, err)

				err = p.RegisterUser(userName, password)
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userName, password, nil)
				require.NoError(t, err)
				require.NotNil(t, res)
			})
		}
	}
}

func TestPure_EncryptDecrypt(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)

				p, err := NewPure(ctx)
				require.NoError(t, err)
				userName := randomString()
				password := randomString()
				dataID := randomString()
				plaintext := randomString()
				err = p.RegisterUser(userName, password)
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userName, password, nil)
				require.NoError(t, err)
				require.NotNil(t, res)

				ciphertext, err := p.EncryptGeneral(userName, dataID, nil, nil, nil, []byte(plaintext))
				require.NoError(t, err)
				decrypted, err := p.Decrypt(res.Grant, userName, dataID, ciphertext)
				require.NoError(t, err)
				require.Equal(t, plaintext, string(decrypted))
			})
		}
	}

}

func TestPure_EncryptDecrypt_Share_Unshare_Admin_ChangePassword(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, buppk, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)

				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				password1 := randomString()
				userId2 := randomString()
				password2 := randomString()
				dataId := randomString()
				plaintext := randomString()
				password3 := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)

				res1, err := p.AuthenticateUser(userId1, password1, nil)
				require.NoError(t, err)
				require.NotNil(t, res1)

				err = p.RegisterUser(userId2, password2)
				require.NoError(t, err)

				res2, err := p.AuthenticateUser(userId2, password2, nil)
				require.NoError(t, err)
				require.NotNil(t, res2)

				kp, err := p.PureCrypto.GenerateUserKey()
				require.NoError(t, err)

				ciphertext, err := p.EncryptGeneral(userId1, dataId, nil, nil, []crypto.PublicKey{kp.PublicKey()}, []byte(plaintext))
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
				adminGrant, err := p.CreateUserGrantAsAdmin(userId1, buppk, DefaultGrantTTL)
				require.NoError(t, err)
				require.NotNil(t, adminGrant)
				decryptedAdmin, err := p.Decrypt(adminGrant, "", dataId, ciphertext)
				require.NoError(t, err)
				require.Equal(t, plaintext, string(decryptedAdmin))

				err = p.ChangeUserPasswordWithGrant(adminGrant, password3)
				require.NoError(t, err)

				res3, err := p.AuthenticateUser(userId1, password3, nil)
				require.NoError(t, err)

				decrypted3, err := p.Decrypt(res3.Grant, "", dataId, ciphertext)
				require.NoError(t, err)
				require.Equal(t, plaintext, string(decrypted3))

				decrypted4, err := p.DecryptWithKey(kp, userId1, dataId, ciphertext)
				require.NoError(t, err)
				require.Equal(t, plaintext, string(decrypted4))

				require.NoError(t, p.Storage.DeleteCellKey(userId1, dataId))
				decrypted3, err = p.Decrypt(res3.Grant, "", dataId, ciphertext)
				require.Error(t, err, storage.ErrNotFound)
				require.Nil(t, decrypted3)
			})
		}
	}
}

func TestPure_ChangeUserPassword(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)
				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				password1 := randomString()
				password2 := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userId1, password1, nil)
				require.NoError(t, err)
				require.NotNil(t, res)

				grant, err := p.DecryptGrantFromUser(res.EncryptedGrant)
				require.NoError(t, err)
				require.NotNil(t, grant)

				require.NoError(t, p.ChangeUserPassword(userId1, password1, password2))

				grant, err = p.DecryptGrantFromUser(res.EncryptedGrant)
				require.Error(t, err)
				var perr *phe.PheError
				require.True(t, errors.As(err, &perr) && perr.Code == phe.PheErrorErrorAESFailed)
				require.Nil(t, grant)
			})
		}
	}
}

func TestPure_GrantExpire(t *testing.T) {
	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)
				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				password1 := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userId1, password1, &SessionParameters{
					TTL: 10 * time.Second,
				})
				require.NoError(t, err)
				require.NotNil(t, res)

				grant, err := p.DecryptGrantFromUser(res.EncryptedGrant)
				require.NoError(t, err)
				require.NotNil(t, grant)
				time.Sleep(time.Second * 5)

				grant, err = p.DecryptGrantFromUser(res.EncryptedGrant)
				require.NoError(t, err)
				require.NotNil(t, grant)
				time.Sleep(time.Second * 6)

				grant, err = p.DecryptGrantFromUser(res.EncryptedGrant)
				require.Error(t, ErrGrantKeyExpired, err)
				require.Nil(t, grant)
			})
		}
	}
}

func TestPure_InvalidateEncryptedUserGrant(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)
				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				password1 := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userId1, password1, nil)
				require.NoError(t, err)
				require.NotNil(t, res)

				require.NoError(t, p.InvalidateEncryptedUserGrant(res.EncryptedGrant))

				grant, err := p.DecryptGrantFromUser(res.EncryptedGrant)
				require.Error(t, err, storage.ErrNotFound)
				require.Nil(t, grant)
			})
		}
	}
}

func TestPure_CreateUserGrantAsAdmin(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, bupk, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)
				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId := randomString()
				password := randomString()
				dataId := randomString()
				text := []byte(randomString())
				err = p.RegisterUser(userId, password)
				require.NoError(t, err)

				ciphertext, err := p.EncryptGeneral(userId, dataId, nil, nil, nil, text)
				require.NoError(t, err)

				grant, err := p.CreateUserGrantAsAdmin(userId, bupk, DefaultGrantTTL)
				require.NoError(t, err)

				plaintext, err := p.Decrypt(grant, "", dataId, ciphertext)
				require.NoError(t, err)
				require.Equal(t, text, plaintext)

			})
		}
	}
}

func TestPure_Roles(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)

				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				userId2 := randomString()
				userId3 := randomString()
				password1 := randomString()
				password2 := randomString()
				password3 := randomString()
				dataId := randomString()
				plaintext := randomString()
				roleName := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)
				err = p.RegisterUser(userId2, password2)
				require.NoError(t, err)
				err = p.RegisterUser(userId3, password3)
				require.NoError(t, err)

				//create role for users 1 and 2
				err = p.CreateRole(roleName, []string{userId1, userId2}...)
				require.NoError(t, err)

				res1, err := p.AuthenticateUser(userId1, password1, nil)
				require.NoError(t, err)
				res2, err := p.AuthenticateUser(userId2, password2, nil)
				require.NoError(t, err)
				res3, err := p.AuthenticateUser(userId3, password3, nil)
				require.NoError(t, err)

				//user1 encrypts to role
				ciphertext, err := p.EncryptGeneral(userId1, dataId, nil, []string{roleName}, nil, []byte(plaintext))
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
			})

		}
	}
}

func TestRotate(t *testing.T) {

	for _, env := range envs {
		t.Run(t.Name()+"_"+env, func(t *testing.T) {
			ctx, buppk, nms, err := BuildContext(false, false, true, false, nil, nil, env)
			require.NoError(t, err)
			p, err := NewPure(ctx)
			require.NoError(t, err)
			firstUserID := randomString()
			firstUserPassword := randomString()
			dataID := randomString()
			text := []byte(randomString())
			require.NoError(t, p.RegisterUser(firstUserID, firstUserPassword))
			for i := 0; i < 20; i++ {
				userID, password := randomString(), randomString()
				require.NoError(t, p.RegisterUser(userID, password))
			}

			authResult1, err := p.AuthenticateUser(firstUserID, firstUserPassword, nil)
			require.NoError(t, err)
			encryptedGrant1 := authResult1.EncryptedGrant

			// token received, do rotation
			ctx, _, _, err = BuildContext(true, false, true, true, nms, buppk, env)
			require.NoError(t, err)
			p, err = NewPure(ctx)
			require.NoError(t, err)
			ciphertext, err := p.Encrypt(firstUserID, dataID, text)
			require.NoError(t, err)

			authResult2, err := p.AuthenticateUser(firstUserID, firstUserPassword, nil)
			require.NoError(t, err)
			encryptedGrant2 := authResult2.EncryptedGrant

			results, err := p.PerformRotation()
			require.NoError(t, err)
			require.Equal(t, uint64(21), results.UsersRotated)
			require.Equal(t, uint64(1), results.GrantsRotated)

			// check that everything works with new keys
			ctx, _, _, err = BuildContext(false, true, true, true, nms, buppk, env)
			require.NoError(t, err)
			p, err = NewPure(ctx)
			require.NoError(t, err)
			pureGrant1, err := p.DecryptGrantFromUser(encryptedGrant1)
			require.NoError(t, err)
			pureGrant2, err := p.DecryptGrantFromUser(encryptedGrant2)
			require.NoError(t, err)

			//decrypt ciphertext with both grants
			decrypted, err := p.Decrypt(pureGrant1, firstUserID, dataID, ciphertext)
			require.NoError(t, err)
			require.Equal(t, decrypted, text)
			decrypted, err = p.Decrypt(pureGrant2, firstUserID, dataID, ciphertext)
			require.NoError(t, err)
			require.Equal(t, decrypted, text)

			// check that everything works with old keys
			ctx, _, _, err = BuildContext(true, false, true, true, nms, buppk, env)
			require.NoError(t, err)
			p, err = NewPure(ctx)
			require.NoError(t, err)
			pureGrant1, err = p.DecryptGrantFromUser(encryptedGrant1)
			require.NoError(t, err)
			pureGrant2, err = p.DecryptGrantFromUser(encryptedGrant2)
			require.NoError(t, err)

			//decrypt ciphertext with both grants
			decrypted, err = p.Decrypt(pureGrant1, firstUserID, dataID, ciphertext)
			require.NoError(t, err)
			require.Equal(t, decrypted, text)
			decrypted, err = p.Decrypt(pureGrant2, firstUserID, dataID, ciphertext)
			require.NoError(t, err)
			require.Equal(t, decrypted, text)
		})
	}
}

func TestPureCrypto_BackupPwdHash(t *testing.T) {
	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, bupk, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)
				p, err := NewPure(ctx)
				require.NoError(t, err)
				userId1 := randomString()
				password1 := randomString()
				err = p.RegisterUser(userId1, password1)
				require.NoError(t, err)

				user, err := p.Storage.SelectUser(userId1)
				require.NoError(t, err)
				descyptedHash, err := p.PureCrypto.Crypto.Decrypt(user.BackupPwdHash, bupk)
				require.NoError(t, err)

				passHash, err := p.PureCrypto.ComputePasswordHash(password1)
				require.Equal(t, passHash, descyptedHash)
			})
		}
	}
}

type CompatibilityData struct {
	EncryptedGrant string `json:"encrypted_grant"`
	UserID1        string `json:"user_id1"`
	UserID2        string `json:"user_id2"`
	Password1      string `json:"password1"`
	Password2      string `json:"password2"`
	DataID1        string `json:"data_id1"`
	DataID2        string `json:"data_id2"`
	Text1          []byte `json:"text1"`
	Text2          []byte `json:"text2"`
	Blob1          []byte `json:"blob1"`
	Blob2          []byte `json:"blob2"`
	Nms            []byte `json:"nms"`
}

func TestCompatibility(t *testing.T) {
	for _, env := range envs {
		t.Run(t.Name()+"_"+env, func(t *testing.T) {
			//read json config
			cdataRaw, err := ioutil.ReadFile(filepath.Join("testdata", fmt.Sprintf("compatibility_data_%s.json", env)))
			require.NoError(t, err)
			var cdata *CompatibilityData
			err = json.Unmarshal(cdataRaw, &cdata)
			require.NoError(t, err)

			//read sql
			stmts, err := readLines(filepath.Join("testdata", fmt.Sprintf("compatibility_tables_%s.sql", env)))
			require.NoError(t, err)

			ctx, _, _, err := BuildContext(false, true, true, true, cdata.Nms, nil, env)

			mdb := ctx.Storage.(*storage.MariaDBPureStorage)
			require.NoError(t, mdb.CleanDB())
			for _, stmt := range stmts {
				require.NoError(t, mdb.ExecuteSQL(stmt))
			}

			p, err := NewPure(ctx)
			require.NoError(t, err)

			grant, err := p.DecryptGrantFromUser(cdata.EncryptedGrant)
			require.NoError(t, err)
			require.NotNil(t, grant)

			res1, err := p.AuthenticateUser(cdata.UserID1, cdata.Password1, nil)
			require.NoError(t, err)
			res2, err := p.AuthenticateUser(cdata.UserID2, cdata.Password2, nil)
			require.NoError(t, err)

			text11, err := p.Decrypt(res1.Grant, "", cdata.DataID1, cdata.Blob1)
			require.NoError(t, err)
			text12, err := p.Decrypt(res2.Grant, cdata.UserID1, cdata.DataID1, cdata.Blob1)
			require.NoError(t, err)
			text21, err := p.Decrypt(res1.Grant, "", cdata.DataID2, cdata.Blob2)
			require.NoError(t, err)
			text22, err := p.Decrypt(res2.Grant, cdata.UserID1, cdata.DataID2, cdata.Blob2)
			require.NoError(t, err)
			require.Equal(t, cdata.Text1, text11)
			require.Equal(t, cdata.Text1, text12)
			require.Equal(t, cdata.Text2, text21)
			require.Equal(t, cdata.Text2, text22)
		})
	}
}

func TestPure_DeleteUser_cascade(t *testing.T) {

	for _, env := range envs {
		for st := 0; st < 2; st++ {
			t.Run(t.Name()+"_"+strg2str(st == 0)+"_"+env, func(t *testing.T) {
				ctx, _, _, err := BuildContext(false, false, st == 0, false, nil, nil, env)
				require.NoError(t, err)

				p, err := NewPure(ctx)
				require.NoError(t, err)
				userName := randomString()
				password := randomString()
				dataID := randomString()
				plaintext := randomString()
				err = p.RegisterUser(userName, password)
				require.NoError(t, err)

				ciphertext, err := p.EncryptGeneral(userName, dataID, nil, nil, nil, []byte(plaintext))
				require.NoError(t, err)

				res, err := p.AuthenticateUser(userName, password, nil)
				require.NoError(t, err)
				require.NotNil(t, res)

				require.NoError(t, p.DeleteUser(userName, true))

				res1, err := p.AuthenticateUser(userName, password, nil)
				require.Error(t, err, storage.ErrNotFound)
				require.Nil(t, res1)

				decrypted, err := p.Decrypt(res.Grant, userName, dataID, ciphertext)
				require.Error(t, err, storage.ErrNotFound)
				require.Nil(t, decrypted)
			})
		}
	}
}

func TestPure_DeleteUser_nocascade(t *testing.T) {
	for _, env := range envs {
		t.Run(t.Name()+"_"+env, func(t *testing.T) {
			ctx, _, _, err := BuildContext(false, false, false, false, nil, nil, env)
			require.NoError(t, err)

			p, err := NewPure(ctx)
			require.NoError(t, err)
			userName := randomString()
			password := randomString()
			dataID := randomString()
			plaintext := randomString()
			err = p.RegisterUser(userName, password)
			require.NoError(t, err)

			ciphertext, err := p.EncryptGeneral(userName, dataID, nil, nil, nil, []byte(plaintext))
			require.NoError(t, err)

			res, err := p.AuthenticateUser(userName, password, nil)
			require.NoError(t, err)
			require.NotNil(t, res)

			require.NoError(t, p.DeleteUser(userName, false))

			res1, err := p.AuthenticateUser(userName, password, nil)
			require.Error(t, err, storage.ErrNotFound)
			require.Nil(t, res1)

			decrypted, err := p.Decrypt(res.Grant, userName, dataID, ciphertext)
			require.NoError(t, err)
			require.Equal(t, decrypted, []byte(plaintext))
		})
	}
}

func TestPure_RecoverUser(t *testing.T) {
	for _, env := range envs {
		t.Run(t.Name()+"_"+env, func(t *testing.T) {
			ctx, _, _, err := BuildContext(false, false, false, false, nil, nil, env)
			require.NoError(t, err)

			p, err := NewPure(ctx)
			require.NoError(t, err)
			userName := randomString()
			password := randomString()
			password2 := randomString()
			dataID := randomString()
			plaintext := randomString()
			err = p.RegisterUser(userName, password)
			require.NoError(t, err)

			ciphertext, err := p.EncryptGeneral(userName, dataID, nil, nil, nil, []byte(plaintext))
			require.NoError(t, err)

			require.NoError(t, p.RecoverUser(userName, password2))

			time.Sleep(time.Second * 10)

			res, err := p.AuthenticateUser(userName, password, nil)
			require.Error(t, err, ErrInvalidPassword)
			require.Nil(t, res)

			res1, err := p.AuthenticateUser(userName, password2, nil)
			require.NoError(t, err)
			require.NotNil(t, res1)

			decrypted, err := p.Decrypt(res1.Grant, "", dataID, ciphertext)
			require.NoError(t, err, storage.ErrNotFound)
			require.Equal(t, decrypted, []byte(plaintext))
		})
	}
}

func TestPure_Throttle(t *testing.T) {
	for _, env := range envs {
		t.Run(t.Name()+"_"+env, func(t *testing.T) {
			ctx, _, _, err := BuildContext(false, false, false, false, nil, nil, env)
			require.NoError(t, err)

			p, err := NewPure(ctx)
			require.NoError(t, err)

			throttlingNumber := uint64(10)
			checkedNumber := uint64(5)
			total := checkedNumber + throttlingNumber

			var succeeded, throttled uint64

			wg := &sync.WaitGroup{}
			wg.Add(int(total))

			r := func() {
				defer wg.Done()
				userName := randomString()
				password := randomString()
				password2 := randomString()
				err = p.RegisterUser(userName, password)
				require.NoError(t, err)

				err = p.RecoverUser(userName, password2)
				if err != nil {
					var httpErr *protos.HttpError
					if errors.As(err, &httpErr) && httpErr.Code == 50070 {
						atomic.AddUint64(&throttled, 1)
					} else {
						t.Fail()
					}
				} else {
					atomic.AddUint64(&succeeded, 1)
				}
			}

			for i := uint64(0); i < total; i++ {
				go r()
			}
			wg.Wait()

			require.Equal(t, throttlingNumber, succeeded)
			require.Equal(t, checkedNumber, throttled)

		})
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func randomString() string {
	b := make([]byte, 16)
	rand.Read(b)
	t := base64.StdEncoding.EncodeToString(b)
	return t
}

/*type DebugClient struct {
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
}*/
