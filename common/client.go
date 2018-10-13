package common

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type VirgilHTTPClient struct {
	Client  HTTPClient
	Address string
	once    sync.Once
}

func (vc *VirgilHTTPClient) Send(method string, urlPath string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(err, "VirgilHTTPClient.Send: marshal payload")
		}
	}

	u, err := url.Parse(vc.Address)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: URL parse")
	}

	u.Path = path.Join(u.Path, urlPath)

	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: new request")
	}

	client := vc.getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: send request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("not found")
	}

	if resp.StatusCode == http.StatusOK {
		if respObj != nil {

			decoder := json.NewDecoder(resp.Body)
			err = decoder.Decode(respObj)
			if err != nil {
				return nil, errors.Wrap(err, "VirgilHTTPClient.Send: unmarshal response object")
			}
		}
		return resp.Header, nil
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "VirgilHTTPClient.Send: read response body")
	}

	return nil, fmt.Errorf("%s", string(respBody))
}

func (vc *VirgilHTTPClient) getHTTPClient() HTTPClient {

	vc.once.Do(func() {

		if vc.Client == nil {

			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
				DualStack: true,
			}

			var netTransport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
				TLSHandshakeTimeout: 10 * time.Second,
			}
			var cli = &http.Client{
				Timeout:   10 * time.Second,
				Transport: netTransport,
			}

			vc.Client = cli
		}
	})

	return vc.Client
}
