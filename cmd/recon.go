package cmd

import (
	"fmt"
	"r4mpartArsenal/internal/recon"

	"github.com/spf13/cobra"
)

var subdomains bool
var ports bool
var dns bool
var whois bool
var ssl bool
var portRange string
var useHttpx bool

var reconCmd = &cobra.Command{
	Use:   "recon [target]",
	Short: "Perform reconnaissance on a target",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Please provide target for reconnaissance. [e.g. facebook.com]")
			return
		}
		target := args[0]
		fmt.Printf("Performing reconnaissance on: %s\n", target)

		if subdomains {
			recon.EnumerateSubdomains(target, useHttpx)
		}
		if ports {
			if portRange == "" {
				recon.ScanPorts(target, "1-1024")
			} else {
				recon.ScanPorts(target, portRange)
			}
		}

		if dns {
			recon.LookupDNS(target)
		}

		if whois {
			recon.PerformWhois(target)
		}

		if ssl {
			recon.AnalyzeSSL(target)
		}

	},
}

func init() {
	rootCmd.AddCommand(reconCmd)

	reconCmd.Flags().BoolVarP(&subdomains, "subdomains", "s", false, "Perform subdomain enumeration")
	reconCmd.Flags().BoolVarP(&ports, "ports", "p", false, "Perform port scanning")
	reconCmd.Flags().BoolVarP(&dns, "dns", "d", false, "Perform DNS lookup")
	reconCmd.Flags().BoolVarP(&whois, "whois", "w", false, "Perform WHOIS lookup")
	reconCmd.Flags().BoolVarP(&ssl, "ssl", "l", false, "Analyze SSL certificate")
	reconCmd.Flags().StringVarP(&portRange, "port-range", "r", "", "Specify custom port range for scanning (e.g., 1-65535)")
	reconCmd.Flags().BoolVarP(&useHttpx, "httpx", "x", false, "Check subdomain reachability with httpx")
}
