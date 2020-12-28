package certgen

import (
	"github.com/blang/semver"
)

// Version of the CLI tool
var Version = semver.MustParse("1.3.0").String()

const (
	// RootFolder is the folder without any additions
	RootFolder = ""
	// ClientCertFolder is the folder name where client certs are stored
	ClientCertFolder = "client_certs"
	// RootCAFolder is the folder name where root CA certs are stored
	RootCAFolder = "root_ca"
	// ServerCertFolder is the folder name where server certs are stored
	ServerCertFolder = "server_certs"
	// CRLCertFolder is the folder containing all CRLs
	CRLCertFolder = "crls"
	// KeyPairFolder is the folder containing random key pairs
	KeyPairFolder = "key_pairs"
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
	// KeyPair is not for certificates, but just public/private pairs
	KeyPair CertificateType = "key_pair"
)

// CertFolderMap maps certificate types to folders
var CertFolderMap = map[CertificateType]string{
	RootCA:            RootCAFolder,
	ServerCertificate: ServerCertFolder,
	ClientCertificate: ClientCertFolder,
	KeyPair:           KeyPairFolder,
	CRL:               CRLCertFolder,
}
