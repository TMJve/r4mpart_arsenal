package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "r4mpart_arsenal",
	Short: "R4mpart Arsenal is a CLI for web application pentesting",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Welcome to R4mpart Arsenal CLI")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

}
