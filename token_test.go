package passw0rd

import (
	"bytes"
	"testing"

	"github.com/passw0rd/phe-go"
	"github.com/stretchr/testify/require"
)

func TestMarshalUpdateToken(t *testing.T) {
	a, b := phe.GenerateClientKey(), phe.GenerateClientKey()
	bToken := MarshalUpdateToken(a, b)
	token, err := UnmarshalUpdateToken(bToken)
	require.NoError(t, err)
	require.True(t, bytes.Equal(a, token.A))
	require.True(t, bytes.Equal(b, token.B))
}
