package template

import (
	"certgen/lib/cher"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"

	"github.com/spf13/viper"
)

type CertInfo struct {
	CertificateExpiryYears int      `json:"certificate_expiry_years"`
	CRLURLs                []string `json:"crl_urls"`
	RootCA                 CAInfo   `json:"root_ca"`
}

type CAInfo struct {
	CommonName   string   `json:"common_name"`
	Country      []string `json:"country"`
	Organisation []string `json:"organisation"`
}

var base = CertInfo{
	CertificateExpiryYears: 10,
	CRLURLs:                []string{"https://s3-eu-west-1.amazonaws.com/crl.dfl.mn/crl.pem"},
	RootCA: CAInfo{
		CommonName:   "DFL Root CA",
		Country:      []string{"GB"},
		Organisation: []string{"Duffleman"},
	},
}

func LoadInfoFromTemplate() (*CertInfo, error) {
	rootDirectory := viper.GetString("SECERTS_ROOT_DIR")
	templatePath := path.Join(rootDirectory, "template.json")

	if _, err := os.Stat(templatePath); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		jsonBytes, err := json.Marshal(base)
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(templatePath, jsonBytes, 0644)
		if err != nil {
			return nil, err
		}

		return nil, cher.New("populate_template", cher.M{
			"path": templatePath,
		})
	}

	var out = CertInfo{}

	jsonBytes, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}
