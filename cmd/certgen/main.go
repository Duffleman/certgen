package main

import (
	"fmt"
	"os"

	"certgen/commands"

	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("SECERTS_ROOT_DIR", "/Users/duffleman/Source/infra-secrets/certificates")

	commands.RootCmd.AddCommand(commands.VersionCmd)
	commands.RootCmd.AddCommand(commands.GenerateRootCACmd)
	commands.RootCmd.AddCommand(commands.GenerateServerCertificateCmd)
	commands.RootCmd.AddCommand(commands.GenerateClientCertificateCmd)
	commands.RootCmd.AddCommand(commands.CreateCRLFileCmd)
}

func main() {
	viper.SetEnvPrefix("CERTGEN")
	viper.AutomaticEnv()

	if err := commands.RootCmd.Execute(); err != nil {
		fmt.Printf("certgen: %s\n", err)
		os.Exit(1)
	}
}
