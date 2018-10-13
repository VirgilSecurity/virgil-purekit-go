package passw0rd

import phe "github.com/passw0rd/phe-go"

type EnrollmentRequest struct {
	Version int `json:"version"`
}

type EnrollmentResponse struct {
	Version    int `json:"version"`
	Enrollment *phe.EnrollmentResponse
}

type EnrollmentRecord struct {
	Version    int                   `json:"version"`
	Enrollment *phe.EnrollmentRecord `json:"enrollment"`
}

type VerifyPasswordRequest struct {
	Version int                        `json:"version"`
	Request *phe.VerifyPasswordRequest `json:"verify_request"`
}

type VerifyPasswordResponse struct {
	Response *phe.VerifyPasswordResponse `json:"response"`
}

type ServerInfo struct {
	Version   int    `json:"version"`
	PublicKey []byte `json:"public_key"`
}

type UpdateToken struct {
	Version int              `json:"version"`
	Token   *phe.UpdateToken `json:"update_token"`
}
