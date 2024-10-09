package recon

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"
)

func spinner(done chan bool) {
	for {
		select {
		case <-done:
			return
		default:
			for _, r := range `-\|/` {
				fmt.Printf("\r%c", r)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// EnumerateSubdomains performs subdomain enumeration on the target
func EnumerateSubdomains(target string, useHttpx bool) {
	fmt.Printf("[INFO] Enumerating subdomains for: %s\n", target)

	done := make(chan bool)
	go spinner(done)

	_, err := exec.LookPath("subfinder")
	if err != nil {
		done <- true
		fmt.Println("[ERROR] Subfinder is not installed, Please install it by running: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
		return
	}

	subfinderCmd := exec.Command("subfinder", "-d", target, "=silent")
	subfinderOutput, err := subfinderCmd.Output()
	if err != nil {
		done <- true
		fmt.Printf("[ERROR Subfinder failed: %v\n]", err)
		return
	}
	if useHttpx {
		fmt.Println("[INFO] Checking subdomain reachability with httpx...")

		_, err := exec.LookPath("httpx")
		if err != nil {
			fmt.Println("[ERROR] httpx is not installed, Please install it by running: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
			return
		}

		httpxCmd := exec.Command("httpx", "-silent", "-status-code")

		httpxCmd.Stdin = bytes.NewReader(subfinderOutput)

		httpxOutput, err := httpxCmd.Output()
		if err != nil {
			done <- true
			fmt.Printf("[ERROR] httpx failed: %v\n", err)
			return
		}

		done <- true
		fmt.Printf("[INFO] Reachable subdomains:\n%s\n", string(httpxOutput))
	} else {

		done <- true
		fmt.Printf("[INFO] Subdomains found:\n%s\n", string(subfinderOutput))
	}
}

// ScanPorts performs port scanning on the target
func ScanPorts(target string, portRange string) {
	fmt.Printf("[INFO] Scanning ports for: %s in range %s\n", target, portRange)
}

// LookupDNS performs DNS lookup on the target
func LookupDNS(target string) {
	fmt.Printf("[INFO] Performing DNS lookup for: %s\n", target)

}

// PerformWhois performs WHOIS lookup on the target
func PerformWhois(target string) {
	fmt.Printf("[INFO] Performing WHOIS lookup for: %s\n", target)

}

// AnalyzeSSL performs SSL certificate analysis on the target
func AnalyzeSSL(target string) {
	fmt.Printf("[INFO] Analyzing SSL certificate for: %s\n", target)

}
