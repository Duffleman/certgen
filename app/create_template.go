package app

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"certgen/lib/cher"
)

func (a *App) createTemplate(certType CertificateType, serialNumber *big.Int) (*x509.Certificate, error) {
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

func loadTemplate(certType CertificateType, now time.Time) (*x509.Certificate, error) {
	switch certType {
	case RootCA:
		return &x509.Certificate{
			Subject:               pkix.Name{},
			NotBefore:             now.Add(-1 * time.Second),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, nil
	case ServerCertificate:
		return &x509.Certificate{
			Subject:   pkix.Name{},
			NotBefore: now.Add(-1 * time.Second),
			KeyUsage:  x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
				x509.ExtKeyUsageServerAuth,
			},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}, nil
	case ClientCertificiate:
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
