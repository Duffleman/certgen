package commands

import (
	"certgen/app"
	"certgen/lib/cher"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	RootCA = "Root CA"
	Server = "Server"
	Client = "Client"
	CRL    = "Revocation list"
)

var InteractiveCmd = &cobra.Command{
	Use:     "interactive",
	Aliases: []string{"i"},
	Short:   "Start an interactive console",
	Args:    cobra.NoArgs,

	RunE: func(cmd *cobra.Command, args []string) error {
		rootDirectory := viper.GetString("SECERTS_ROOT_DIR")

		app := &app.App{
			RootDirectory: rootDirectory,
		}

		_, certType, err := certificateTypesPrompt.Run()
		if err != nil {
			return err
		}

		switch certType {
		case RootCA:
			return app.GenerateRootCA()
		case CRL:
			return app.GenerateCRL()
		case Server:
			certName, err := namePrompt.Run()
			if err != nil {
				return err
			}

			return app.GenerateServerCertificate(certName)
		case Client:
			certName, err := namePrompt.Run()
			if err != nil {
				return err
			}

			password, err := passwordPrompt.Run()
			if err != nil {
				return err
			}

			return app.GenerateClientCertificate(certName, password)
		default:
			return cher.New("invalid_certificate_type", cher.M{"type": certType})
		}
	},
}

var certificateTypesPrompt = promptui.Select{
	Label: "Certificate to generate",
	Items: []string{RootCA, Server, Client, CRL},
}

var namePrompt = promptui.Prompt{
	Label: "Name",
	Validate: func(input string) error {
		if len(input) <= 3 {
			return cher.New("name_too_short", nil)
		}

		return nil
	},
}

var passwordPrompt = promptui.Prompt{
	Label:       "Password",
	Mask:        '*',
	HideEntered: true,
	Validate: func(input string) error {
		if len(input) == 0 {
			return cher.New("password_too_short", nil)
		}

		return nil
	},
}
