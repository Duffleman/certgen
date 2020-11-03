package certgen

import (
	"github.com/blang/semver"
)

var Version = semver.MustParse("0.0.1").String()

const (
	RootCAFolder     = "root_ca"
	ClientCertFolder = "client_certs"
)
