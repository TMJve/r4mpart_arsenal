package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// ASCII art for r4mpartArsenal
const asciiArt = `
  _____  _  _                              _                                     _      
 |  __ \| || |                            | |                                   | |     
 | |__) | || |_ _ __ ___  _ __   __ _ _ __| |_    __ _ _ __ ___  ___ _ __   __ _| | ___ 
 |  _  /|__   _| '_ \ '_ \| '_ \ / _` + "`" + ` | '__| __|  / _` + "`" + ` | '__/ __|/ _ \ '_ \ / _` + "`" + ` | |/ _ \
 | | \ \   | | | | | | | | |_) | (_| | |  | |_  | (_| | |  \__ \  __/ | | | (_| | |  __/
 |_|  \_\  |_| |_| |_| |_| .__/ \__,_|_|   \__|  \__,_|_|  |___/\___|_| |_|\__, |_|\___|
                         | |                                            __        
                         |_|                                                    
`

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "r4mpartArsenal",
	Short: "R4mpart Arsenal is a CLI for web application pentesting and bug bounty",
	Long:  asciiArt + "\nR4mpart Arsenal is a CLI for web application pentesting and bug bounty.",
	Run: func(cmd *cobra.Command, args []string) {
		// Display ASCII art and a welcome message
		fmt.Println(asciiArt)
		fmt.Println("Welcome to R4mpart Arsenal CLI. Use --help to see available commands.")
	},
}

// Override the default help function to include ASCII art
func customHelpFunc(cmd *cobra.Command, args []string) {
	fmt.Println(asciiArt)
	cmd.Help()
}

func Execute() {
	// Set the custom help function
	cobra.OnInitialize(func() {
		rootCmd.SetHelpFunc(customHelpFunc)
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Register commands here
}
