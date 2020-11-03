package app

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"certgen"
	"certgen/lib/cher"
)

// createTemplate will create an x509 certificate to use as a template to create
// an actual certificate you can use. It will also fill in some key details for
// you
func (a *App) createTemplate(certType certgen.CertificateType, serialNumber *big.Int) (*x509.Certificate, error) {
	now := time.Now()

	base, err := loadTemplate(certType, now)
	if err != nil {
		return nil, err
	}

	base.SerialNumber = serialNumber
	base.Subject.Country = a.CertificateInformation.Country
	base.Subject.Organization = a.CertificateInformation.Organisation
	base.NotAfter = now.AddDate(a.CertificateInformation.CertificateExpiryYears, 0, 0)

	return base, nil
}

// loadTemplate will load a raw x509 certificate with no information to use as a
// template in x509.CreateCertificate
func loadTemplate(certType certgen.CertificateType, now time.Time) (*x509.Certificate, error) {
	switch certType {
	case certgen.RootCA:
		return &x509.Certificate{
			Subject:               pkix.Name{},
			NotBefore:             now.Add(-1 * time.Second),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, nil
	case certgen.ServerCertificate:
		return &x509.Certificate{
			Subject:   pkix.Name{},
			NotBefore: now.Add(-1 * time.Second),
			KeyUsage:  x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}, nil
	case certgen.ClientCertificate:
		return &x509.Certificate{
			Subject:   pkix.Name{},
			NotBefore: now.Add(-1 * time.Second),
			KeyUsage:  x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}, nil
	default:
		return nil, cher.New("unknown_cert_type", cher.M{"type": certType})
	}
}
