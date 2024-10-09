package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "r4mpart_arsenal",
	Short: "R4mpart Arsenal is a CLI for web application pentesting and bug bounty",
	Run: func(cmd *cobra.Command, args []string) {
		// Use raw string literals for ASCII art
		// fmt.Println(`
		//   _____  _  _                              _                                     _
		//  |  __ \| || |                            | |                                   | |
		//  | |__) | || |_ _ __ ___  _ __   __ _ _ __| |_    __ _ _ __ ___  ___ _ __   __ _| |
		//  |  _  /|__   _| '_ \ '_ \| '_ \ / _` + "`" + ` | '__| __|  / _` + "`" + ` | '__/ |
		//  | | \ \   | | | | | | | | |_) | (_| | |  | |_  | (_| | |  \__ \  __/ | | | (_| | |
		//  |_|  \_\  |_| |_| |_| |_| .__/ \__,_|_|   \__|  \__,_|_|  |___/\___|_| |_|\__,_|_|
		//                          | |
		//                          |_|
		// `)
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
	// Register commands here
}
