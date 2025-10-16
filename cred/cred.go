package cred

type Credential struct {
	ApiVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Status     CredentialStatus `json:"status"`
}

type CredentialStatus struct {
	ExpirationTimestamp   string `json:"expirationTimestamp,omitempty"`
	Token                 string `json:"token,omitempty"`
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	ClientKeyData         string `json:"clientKeyData,omitempty"`
}
