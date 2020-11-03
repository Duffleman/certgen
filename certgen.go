package certgen

import (
	"github.com/blang/semver"
)

// Version of the CLI tool
var Version = semver.MustParse("0.0.1").String()

const (
	// RootFolder is the folder without any additions
	RootFolder = ""
	// ClientCertFolder is the folder name where client certs are stored
	ClientCertFolder = "client_certs"
	// RootCAFolder is the folder name where root CA certs are stored
	RootCAFolder = "root_ca"
	// ServerCertFolder is the folder name where server certs are stored
	ServerCertFolder = "server_certs"
)

// CertificateType represents a type of certificate this tool handles
type CertificateType string

const (
	// RootCA is for root CAs
	RootCA CertificateType = "root_ca"
	// ServerCertificate is for server certificates
	ServerCertificate CertificateType = "server_certificate"
	// ClientCertificate is for client certificates
	ClientCertificate CertificateType = "client_certificate"
	// CRL is for certificate revocation lists
	CRL CertificateType = "certificate_revocation"
)

// CertFolderMap maps certificate types to folders
var CertFolderMap = map[CertificateType]string{
	RootCA:            RootCAFolder,
	ServerCertificate: ServerCertFolder,
	ClientCertificate: ClientCertFolder,
	CRL:               RootFolder,
}
