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
