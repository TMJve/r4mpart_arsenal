package recon

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
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

func ActiveDNSEnumeration(target, wordlistPath string) {
	fmt.Printf("[INFO] Starting active DNS enumeration for: %s\n", target)

	// Brute-force subdomains using a wordlist
	subdomains := BruteForceSubdomains(target, wordlistPath)
	fmt.Printf("[INFO] Brute-forced subdomains:\n%v\n", subdomains)

	// Perform A and AAAA record lookups
	aRecords, _ := LookupARecords(target)
	fmt.Printf("[INFO] A records for %s: %v\n", target, aRecords)

	aaaaRecords, _ := LookupAAAARecords(target)
	fmt.Printf("[INFO] AAAA records for %s: %v\n", target, aaaaRecords)

	// Perform DNS lookups for MX, NS, and CNAME records
	mxRecords, _ := LookupMXRecords(target)
	fmt.Printf("[INFO] MX records for %s: %v\n", target, mxRecords)

	nsRecords, _ := LookupNSRecords(target)
	fmt.Printf("[INFO] NS records for %s: %v\n", target, nsRecords)

	cnameRecord, _ := LookupCNAME(target)
	fmt.Printf("[INFO] CNAME for %s: %v\n", target, cnameRecord)
}

func BruteForceSubdomains(domain, wordlistPath string) []string {
	var subdomains []string
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("[ERROR] Could not open wordlist: %v\n", err)
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := fmt.Sprintf("%s.%s", scanner.Text(), domain)
		ips, err := LookupARecords(subdomain)
		if err == nil && len(ips) > 0 {
			fmt.Printf("[INFO] Found subdomain: %s\n", subdomain)
			subdomains = append(subdomains, subdomain)
		}
	}
	return subdomains
}

func LookupARecords(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ip := range ips {
		if ip.To4() != nil {
			results = append(results, ip.String())
		}
	}
	return results, nil
}

// Lookup AAAA Records (IPv6)
func LookupAAAARecords(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ip := range ips {
		if ip.To16() != nil && ip.To4() == nil {
			results = append(results, ip.String())
		}
	}
	return results, nil
}

// Lookup MX Records (Mail Exchange)
func LookupMXRecords(domain string) ([]string, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, mx := range mxRecords {
		results = append(results, fmt.Sprintf("%s (Priority: %d)", mx.Host, mx.Pref))
	}
	return results, nil
}

// Lookup NS Records (Name Servers)
func LookupNSRecords(domain string) ([]string, error) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ns := range nsRecords {
		results = append(results, ns.Host)
	}
	return results, nil
}

// Lookup CNAME Records (Canonical Name)
func LookupCNAME(domain string) (string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return "", err
	}
	return cname, nil
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
