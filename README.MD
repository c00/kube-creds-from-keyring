# Kube Credentials from Keyring

Get kubectl credentials from your keyring.

Why? Because having your tokens / certificates in `~/.kube/config` leaves it very vulnerable to info stealers etc. Having the information in your keyring adds a layer of security and audit.

Use in combination with [`keepass2keyring`](https://github.com/c00/keepass2env) to easily extract the data from your keepass database into your keyring.

## Installation

```sh
go install github.com/c00/kube-creds-from-keyring/cmd/kube-creds-from-keyring@latest
```

## Usage

This assumes the default keyring. It also assumes the attributes `service` (default: `keepass2keyring`) and `application`. The values can be set through parameters.

```sh
kube-creds-from-keyring -u "Some-API-Token" -s "my-stuff"
```

This will look in your keyring for a value with the attributes:

- `service`: `my-stuff`
- `username`: `Some-API-Token`

assuming it finds an entry, it will return json that kubectl expects:

```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "expirationTimestamp": "2025-10-16T15:28:29+07:00",
    "token": "whateverthevaluofyourapitokeninthekeyringwaswowwhyareyoustillreadingthis"
  }
}
```

Using client certs instead? We got you:

```sh
kube-creds-from-keyring -v "Some-client-certificate" -k "Some-client-key" -s "my-stuff"
```

This will look in your keyring for 2 values:

- For the certificate:
  - `service`: `my-stuff`
  - `username`: `Some-client-certificate`
- For the key:
  - `service`: `my-stuff`
  - `username`: `Some-client-key`

If found, it will return the following:

```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "expirationTimestamp": "2025-10-16T15:28:29+07:00",
    "clientCertificateData": "certificatedatahere",
    "clientKeyData": "keydatahere"
  }
}
```

If your certificate and key data are in base64 format, just add the `-d` flag:

```sh
kube-creds-from-keyring -v "Some-client-certificate" -k "Some-client-key" -s "my-stuff" -d
```

This flag will base64 decode the values from the keyring before putting it in the json.

## Usage with kubectl

Update your kubeconfig file (normally at `~/.kube/config`)

```yaml
# ... 
users:
- name: some-user-with-token
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kube-creds-from-keyring
      args:
        - -s=my-stuff
        - -u=Some-API-Token
      interactiveMode: IfAvailable
      provideClusterInfo: false
- name: some-user-with-client-certs
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kube-creds-from-keyring
      args:
        - -s=my-stuff
        - -c=Some-client-certificate
        - -k=Some-client-key
        - -d # Optional: base64 decode
      interactiveMode: IfAvailable
      provideClusterInfo: false
```