// scan provides method to scan ports, and is used by portscan and portscanservice.
// project home: https://github.com/paulfdunn/portscan
package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ID struct {
	ID string
}

type Results []Result

type Result struct {
	IP    string
	Port  string
	Error *string
}

// The constants in this section are used by portscan and portscanservice, and may not be used
// by this package. They are here because both portscanservice and portscan have a main function,
// and thus cannot import each other. Thus this package is used for both the scan function and
// common code, constants, etc.
const (
	// Both the service and CLI could take the port as a parameter, but I am limiting scope and
	// putting in a hardcoded value.
	DefaultServicePort = "8000"

	InvalidIPsCLI     = "Invalid IP entry. Must be a space delimited list of IP addresses."
	InvalidIPsService = "Invalid IP entry. Must be a CSV list of IP addresses."
	InvalidPort       = "Invalid port entry. Must be an integer [0, 65535]"
	MissingPort       = "No port set; call SetPort to set the target port."
	MissingIPs        = "No IPs set; call setIPs to set the target IP addresses."
	ShowIPs           = "Current IPs: "
	ShowPort          = "Current port: "

	NoError = "none"

	// ServiceAppName is returned in ServerHeader so callers know they are talking to this service.
	ServiceAppName = "portscanservice"
	// ServiceHeader returns AppName, see above.
	ServiceHeader = "Server"
)

const (
	minValidPort = 0
	maxValidPort = 65535

	// https://golang.org/src/net/dial.go?s=9833:9881#L307
	// For IP networks, the network must be "ip", "ip4" or "ip6" followed by a colon
	// and a literal protocol number or a protocol name...
	networkType = "tcp"
)

func (sr Results) String() string {
	out := ""
	for i := range sr {
		out += fmt.Sprintf("IP:  %-15s| Port: %-5s| ", sr[i].IP, sr[i].Port)
		if sr[i].Error == nil {
			out += fmt.Sprintf("Error: none\n")
		} else {
			out += fmt.Sprintf("Error: %+v\n", *sr[i].Error)
		}
	}
	return out
}

// Scan performs a port scan of the provided port (string with no leading ":"), IPs, in
// the specified number of threads (asynchronous processes), with the specified timeout (seconds).
// Inputs should be validated prior to calling using ValidatePort and ValidateIPs. (Validation
// is done separately to allow callers to verify data when supplied by the user, so the user
// can be notified at that point and the problem corrected.)
func Scan(port string, ips []string, threads int, timeout time.Duration) Results {
	results := make([]Result, len(ips))
	resultChan := make(chan Result, len(ips))
	var wg sync.WaitGroup
	tasks := make(chan string, len(ips))
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(taskChan <-chan string, port string, rslt chan<- Result, tout time.Duration) {
			for ip := range taskChan {
				addr := ip + ":" + port
				conn, err := net.DialTimeout(networkType, addr, tout)
				if err != nil {
					es := fmt.Sprintf("%+v", err)
					rslt <- Result{IP: ip, Port: port, Error: &es}
					continue
				}
				conn.Close()
				none := NoError
				rslt <- Result{IP: ip, Port: port, Error: &none}
			}
			wg.Done()
		}(tasks, port, resultChan, timeout)
	}

	for i := range ips {
		tasks <- ips[i]
	}
	close(tasks)

	wg.Wait()
	close(resultChan)
	index := 0
	for r := range resultChan {
		results[index] = r
		index++
	}

	return results
}

// ValidateIPs will validate inputIPs as valid IPv4 or IPv6. If any IP is invalid, no IPs are returned.
func ValidateIPs(inputIPs []string, cli bool) ([]string, error) {
	if len(inputIPs) == 0 {
		if cli {
			return []string{}, fmt.Errorf("%s", InvalidIPsCLI)
		}
		return []string{}, fmt.Errorf("%s", InvalidIPsService)
	}
	ipsOut := make([]string, len(inputIPs))
	for i := 0; i < len(inputIPs); i++ {
		ip := net.ParseIP(inputIPs[i])
		if ip == nil {
			if cli {
				return []string{}, fmt.Errorf("%s invalid IP: %s", InvalidIPsCLI, inputIPs[i])
			}
			return []string{}, fmt.Errorf("%s invalid IP: %s", InvalidIPsService, inputIPs[i])
		}
		thisIP := ip.String()
		if strings.Contains(thisIP, ":") {
			thisIP = "[" + thisIP + "]"
		}
		ipsOut[i] = thisIP
	}

	return ipsOut, nil
}

// ValidatePort will validate that the port is within the valid range. A string is accepted for callers
// who may have received user input from a query string.
func ValidatePort(port string) (string, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < minValidPort || p > maxValidPort {
		return "", fmt.Errorf("%s", InvalidPort)
	}
	return fmt.Sprintf("%d", p), nil
}
