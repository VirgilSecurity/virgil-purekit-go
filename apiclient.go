package passw0rd

import (
	"net/http"
	"path"
	"sync"

	"github.com/passw0rd/sdk-go/common"
)

type APIClient struct {
	AppID      string
	URL        string
	HTTPClient *common.VirgilHTTPClient
	once       sync.Once
}

func (c *APIClient) GetEnrollment(req *EnrollmentRequest) (resp *EnrollmentResponse, err error) {
	_, err = c.getClient().Send(http.MethodPost, path.Join(c.AppID, "enroll"), req, &resp)
	return
}

func (c *APIClient) VerifyPassword(req *VerifyPasswordRequest) (resp *VerifyPasswordResponse, err error) {

	_, err = c.getClient().Send(http.MethodPost, path.Join(c.AppID, "verify-password"), req, &resp)
	return
}

func (c *APIClient) getClient() *common.VirgilHTTPClient {
	c.once.Do(func() {
		if c.HTTPClient == nil {
			c.HTTPClient = &common.VirgilHTTPClient{
				Address: c.getUrl(),
			}
		}
	})
	return c.HTTPClient
}

func (c *APIClient) getUrl() string {
	if c.URL != "" {
		return c.URL
	}
	return "http://192.168.235.133:8080"
}
