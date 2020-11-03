package app

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"certgen"
	"certgen/lib/cher"
)

type certInfo struct {
	ChangeDetection        bool     `json:"i_changed_this_file"`
	CertificateExpiryYears int      `json:"certificate_expiry_years"`
	CRLURLs                []string `json:"crl_urls"`
	RootCA                 caInfo   `json:"root_ca"`
	Country                []string `json:"country"`
	Organisation           []string `json:"organisation"`
}

type caInfo struct {
	CommonName string `json:"common_name"`
}

var base = certInfo{
	CertificateExpiryYears: 10,
	CRLURLs:                []string{"https://s3-eu-west-1.amazonaws.com/crl.dfl.mn/crl.pem"},
	RootCA: caInfo{
		CommonName: "DFL Root CA",
	},
	Country:      []string{"GB"},
	Organisation: []string{"Duffleman"},
}

var folders = []string{
	certgen.ClientCertFolder,
	certgen.RootCAFolder,
	certgen.ServerCertFolder,
}

func (a *App) checkForInit() error {
	if err := os.MkdirAll(a.RootDirectory, 0777); err != nil {
		return err
	}

	for _, f := range folders {
		path := path.Join(a.RootDirectory, f)
		if err := os.MkdirAll(path, 0777); err != nil {
			return err
		}
	}

	templatePath := path.Join(a.RootDirectory, "template.json")

	if _, err := os.Stat(templatePath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		jsonBytes, err := json.Marshal(base)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(templatePath, jsonBytes, 0644)
		if err != nil {
			return err
		}

		return cher.New("populate_template", cher.M{
			"path": templatePath,
		})
	}

	var out = certInfo{}

	jsonBytes, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonBytes, &out)
	if err != nil {
		return err
	}

	if !out.ChangeDetection {
		return cher.New("populate_template", cher.M{
			"path": templatePath,
		})
	}

	a.CertificateInformation = &out

	return nil
}
