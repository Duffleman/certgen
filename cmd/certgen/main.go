package main

import (
	"encoding/json"
	"fmt"
	"os"

	"certgen/commands"
	"certgen/lib/cher"

	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("SECERTS_ROOT_DIR", "/Users/duffleman/Source/infra-secrets/certificates")

	commands.RootCmd.AddCommand(commands.VersionCmd)
	commands.RootCmd.AddCommand(commands.GenerateRootCACmd)
	commands.RootCmd.AddCommand(commands.GenerateClientCertificateCmd)
	commands.RootCmd.AddCommand(commands.GenerateServerCertificateCmd)
	commands.RootCmd.AddCommand(commands.CreateCRLFileCmd)
}

func main() {
	viper.SetEnvPrefix("CERTGEN")
	viper.AutomaticEnv()

	if err := commands.RootCmd.Execute(); err != nil {
		if c, ok := err.(cher.E); ok {
			bytes, err := json.MarshalIndent(c, "", "  ")
			if err != nil {
				panic(err)
			}

			fmt.Println(string(bytes))
			os.Exit(1)
		}

		fmt.Println(err)
		os.Exit(1)
	}
}
