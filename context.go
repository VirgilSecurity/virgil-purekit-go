package passw0rd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/passw0rd/phe-go"

	"github.com/pkg/errors"
)

type Context struct {
	AppId        string
	PHEClients   map[int]*phe.Client
	UpdateTokens map[int]*phe.UpdateToken
	Version      int
}

func CreateContext(appId, clientPrivateKey, serverPublicKey string, updateTokens ...string) (*Context, error) {

	if len(appId) != 32 || clientPrivateKey == "" || serverPublicKey == "" {
		return nil, errors.New("all parameters are mandatory")
	}

	_, err := hex.DecodeString(appId)
	if err != nil {
		return nil, errors.New("invalid appID")
	}

	priv, err := base64.StdEncoding.DecodeString(clientPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid private key")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(serverPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "invalid public key")
	}

	var info *ServerInfo
	err = json.Unmarshal(pubBytes, &info)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse public key")
	}

	currentPriv, currentPub := priv, info.PublicKey
	pheClient, err := phe.NewClient(currentPriv, currentPub)

	if err != nil {
		return nil, errors.Wrap(err, "could not create PHE client")
	}

	phes := make(map[int]*phe.Client)
	phes[info.Version] = pheClient

	tokens, err := parseTokens(updateTokens...)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse update tokens")
	}

	currentVersion := info.Version

	var tokenMap map[int]*phe.UpdateToken

	if len(tokens) > 0 {
		tokenMap = make(map[int]*phe.UpdateToken)
		for _, token := range tokens {
			if token.Version != currentVersion+1 {
				return nil, fmt.Errorf("incorrect token version %d", token.Version)
			}

			nextPriv, nextPub, err := phe.RotateClientKeys(currentPriv, currentPub, token.Token)
			if err != nil {
				return nil, errors.Wrap(err, "could not update keys using token")
			}

			nextClient, err := phe.NewClient(nextPriv, nextPub)
			if err != nil {
				return nil, errors.Wrap(err, "could not create PHE client")
			}

			phes[token.Version] = nextClient
			currentPriv, currentPub = nextPriv, nextPub
			currentVersion = token.Version
			tokenMap[token.Version] = token.Token
		}

	}

	return &Context{
		PHEClients:   phes,
		AppId:        appId,
		Version:      currentVersion,
		UpdateTokens: tokenMap,
	}, nil
}

func parseTokens(tokens ...string) (parsedTokens []*UpdateToken, err error) {
	if len(tokens) == 0 {
		return nil, nil
	}

	for _, tokenStr := range tokens {
		tokenJson, err := base64.StdEncoding.DecodeString(tokenStr)
		if err != nil {
			return nil, err
		}
		var token *UpdateToken
		err = json.Unmarshal(tokenJson, &token)
		if err != nil {
			return nil, err
		}
		parsedTokens = append(parsedTokens, token)
	}

	sort.Slice(parsedTokens, func(i, j int) bool { return parsedTokens[i].Version < parsedTokens[j].Version })

	return
}
