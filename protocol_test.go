package passw0rd

import (
	"encoding/base64"
	"testing"

	phe "github.com/passw0rd/phe-go"
	"github.com/stretchr/testify/assert"
)

func TestProtocol_EnrollAccount(t *testing.T) {
	priv := phe.GenerateClientKey()
	privStr := base64.StdEncoding.EncodeToString(priv)
	pubStr := "eyJwdWJsaWNfa2V5IjoiQk1GOXVaR3hvY3dYR0U3a0ZFMDlOeHptandrTTk4aEFQQUVKRHh4OHpmVk1OcCs0anhJbEl4dTZLQXE4eTBVSkhhMTIzSVhUQ0duQjBscVRIUnNLYktNPSIsInZlcnNpb24iOjF9"
	token1 := "eyJ1cGRhdGVfdG9rZW4iOnsiYSI6Ik5jQW9yWXdvU0tOL3l1L2dOblZGUVY0REdHaXhlVG9jKzBxZ1lxRlZqOG89IiwiYiI6IjlRei9PVTdWdXpkY2EyZUtTeEpvbEVqaTdWcTVHNTVpNWpCWTQ0QVovVVk9In0sInZlcnNpb24iOjJ9"
	appId := "307f21b4cdbd4de6ac88362817e6cd94"

	context, err := CreateContext(appId, privStr, pubStr)
	assert.NoError(t, err)

	proto, err := NewProtocol(context)
	assert.NoError(t, err)

	rec, key, err := proto.EnrollAccount("p@ssw0Rd")
	assert.NoError(t, err)
	assert.True(t, len(rec) > 0)
	assert.True(t, len(key) == 32)

	key1, err := proto.VerifyPassword("p@ssw0Rd", rec)
	assert.NoError(t, err)
	assert.Equal(t, key, key1)

	key2, err := proto.VerifyPassword("passw0Rd", rec)
	assert.EqualError(t, err, ErrInvalidPassword.Error())
	assert.Nil(t, key2)

	//rotate happened
	context, err = CreateContext(appId, privStr, pubStr, token1)
	assert.NoError(t, err)
	proto, err = NewProtocol(context)
	assert.NoError(t, err)

	newRec, err := proto.UpdateEnrollmentRecord(rec)
	assert.NoError(t, err)

	key3, err := proto.VerifyPassword("p@ssw0Rd", newRec)
	assert.NoError(t, err)
	assert.Equal(t, key, key3)

}
