package certgen

import (
	"github.com/blang/semver"
)

var Version = semver.MustParse("0.0.1").String()

const (
	ClientCertFolder = "client_certs"
	RootCAFolder     = "root_ca"
	ServerCertFolder = "server_certs"
)
