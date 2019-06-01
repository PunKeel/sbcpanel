package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/safebrowsing"
)

var (
	apiKeyFlag                   = flag.String("apikey", "", "specify your Safe Browsing API key")
	databaseFlag                 = flag.String("db", "", "path to the Safe Browsing database. By default persistent storage is disabled (not recommended).")
	domainsFlag                  = flag.String("f", "/etc/userdomains", "path to the userdomains file containing a list of 'domain: user' formatted lines.")
	ignoreSuspended              = flag.Bool("ignoresuspended", true, "ignore suspended accounts. True by default.")
	cpanelSuspendedAccountsCache = make(map[string]bool)
)

const usage = `sbcpanel: command-line tool to lookup URLs hosted on this cPanel
machine with Safe Browsing. Tool reads one URL per line from /etc/userdomains
and checks every URL against the Safe Browsing API. The Safe or Unsafe verdict
is printed to STDOUT. If an error occurred, debug information may be printed
to STDERR.


Exit codes (bitwise OR of following codes):
  0  if and only if all URLs were looked up and are safe.
  1  if at least one URL is not safe.
  2  if at least one URL lookup failed.
  4  if the input was invalid.


Usage: %s -apikey=$APIKEY
`

const (
	codeSafe = (1 << iota) / 2 // Sequence of 0, 1, 2, 4, 8, etc...
	codeUnsafe
	codeFailed
	codeInvalid
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *apiKeyFlag == "" {
		fmt.Fprintln(os.Stderr, "No -apikey specified")
		os.Exit(codeInvalid)
	}
	sb, err := safebrowsing.NewSafeBrowser(safebrowsing.Config{
		APIKey: *apiKeyFlag,
		DBPath: *databaseFlag,
		Logger: os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to initialize Safe Browsing client: ", err)
		os.Exit(codeInvalid)
	}

	code := codeSafe

	f, err := os.Open(*domainsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to open file /etc/localdomains: ", err)
		os.Exit(codeInvalid)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		url, account := parseLine(line)
		if account == "" || account == "*" {
			continue
		}

		if *ignoreSuspended && IsSuspendedOncPanel(account) {
			continue
		}

		threats, err := sb.LookupURLs([]string{url})
		if err != nil {
			fmt.Fprintln(os.Stdout, "Unknown URL:", url)
			fmt.Fprintln(os.Stderr, "Lookup error:", err)
			code |= codeFailed
		} else if len(threats[0]) != 0 {
			fmt.Fprintln(os.Stdout, strings.Repeat("-", 10))
			fmt.Fprintf(os.Stdout, "Threat found: %s\n", threats[0][0].ThreatType)
			fmt.Fprintf(os.Stdout, "Account: %s\n", account)
			safe_url := strings.Replace(url, ".", "[.]", -1)
			safe_url = strings.Replace(safe_url, "http://", "hxxp://", -1)
			safe_url = strings.Replace(safe_url, "https://", "hxxps://", -1)
			fmt.Fprintf(os.Stdout, "Domain: %s\n", safe_url)
			fmt.Fprintln(os.Stdout, strings.Repeat("-", 10))
			fmt.Fprintln(os.Stdout, "")
			code |= codeUnsafe
		}
	}

	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "Unable to read input:", scanner.Err())
		code |= codeInvalid
	}

	os.Exit(code)
}

func IsSuspendedOncPanel(account string) (isSuspended bool) {
	if val, ok := cpanelSuspendedAccountsCache[account]; ok {
		return val
	}
	accountFile := "/var/cpanel/users/" + account

	f, err := os.Open(accountFile)
	if err != nil {
		// The account does not exist
		cpanelSuspendedAccountsCache[account] = false
		return false
	}

	result := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "SUSPENDED=1" {
			result = true
		}
	}

	cpanelSuspendedAccountsCache[account] = result
	return result
}

func parseLine(line string) (url string, account string) {
	parts := strings.Split(line, ": ")
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
