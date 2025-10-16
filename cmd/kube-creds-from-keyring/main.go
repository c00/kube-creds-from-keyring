package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/c00/kube-creds-from-keyring/cred"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

const version = "0.0.1"

func main() {
	var userName string
	var certName string
	var keyName string
	var serviceName string
	var decodeCerts bool

	var rootCmd = &cobra.Command{
		Use:     "kube-creds-from-keyring",
		Example: "kube-creds-from-keyring -u docker-token",
		Short:   "Kubectl Credential Exec Plugin to get tokens and certs from the system keyring",
		Version: version,
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := "token"
			if userName == "" {
				mode = "cert"
			}

			if mode == "cert" && (certName == "" || keyName == "") {
				return fmt.Errorf("set --user\n or --cert and --key")
			}

			crd := cred.Credential{
				ApiVersion: "client.authentication.k8s.io/v1",
				Kind:       "ExecCredential",
				Status: cred.CredentialStatus{
					ExpirationTimestamp: time.Now().Add(2 * time.Hour).Format(time.RFC3339),
				},
			}

			if mode == "token" {
				secret, err := keyring.Get(serviceName, userName)
				if err != nil {
					return fmt.Errorf("cannot get secret from keyring: %w", err)
				}

				crd.Status.Token = secret
			} else {
				cert, err := keyring.Get(serviceName, certName)
				if err != nil {
					return fmt.Errorf("cannot get cert from keyring: %w", err)
				}

				crd.Status.ClientCertificateData = cert

				key, err := keyring.Get(serviceName, keyName)
				if err != nil {
					return fmt.Errorf("cannot get key from keyring: %w", err)
				}
				crd.Status.ClientKeyData = key

				if decodeCerts {
					decoded, err := base64.StdEncoding.DecodeString(crd.Status.ClientCertificateData)
					if err != nil {
						return fmt.Errorf("cannot base64 decode client certificate: %w", err)
					}
					crd.Status.ClientCertificateData = string(decoded)

					decoded, err = base64.StdEncoding.DecodeString(crd.Status.ClientKeyData)
					if err != nil {
						return fmt.Errorf("cannot base64 decode client key: %w", err)
					}
					crd.Status.ClientKeyData = string(decoded)
				}
			}

			bytes, err := json.Marshal(crd)
			if err != nil {
				return fmt.Errorf("cannot marshall credentials: %w", err)
			}

			fmt.Fprintf(os.Stdout, "%v", string(bytes))

			return nil
		},
	}

	rootCmd.Flags().StringVarP(&userName, "user", "u", "", "The username attribute value")
	rootCmd.Flags().StringVarP(&certName, "cert", "c", "", "The username attribute value for the cert")
	rootCmd.Flags().StringVarP(&keyName, "key", "k", "", "The username attribute value for the key")
	rootCmd.Flags().StringVarP(&serviceName, "service", "s", "keepass2keyring", "Value for the attribute 'service'")
	rootCmd.Flags().BoolVarP(&decodeCerts, "decode", "d", false, "base64 decode the cert and key")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
