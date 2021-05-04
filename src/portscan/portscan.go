// portscan.go implements the CLI portion of https://github.com/paulfdunn/portscan
// Note that the CLI can be used either in a standalone mode (this application performs
// the scan), or it can use the ReST API provided by portscanservice.go.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/paulfdunn/portscan/src/scan"
)

const (
	exitCodeNoService int = iota
	exitCodeWrongServer
)

const (
	appName = "portscan"
	// threads could be a user input, if desired; easy change.
	threads = 10

	noInput = "No input received; ? for help."
)

var (
	serviceurl = ""
	serviceip  = flag.String("serviceip", "",
		"IP address or hostname for the portscanservice. "+
			"Default is for this app to run the scan without use of the service.")
	// port is the string representation of the integer port number, no leading ":"
	port            string
	ips             []string
	results         scan.Results
	pendingResultID string

	prompt = appName + ">"

	// timeout is timeout for scan requests.
	timeout = time.Duration(2) * time.Second
)

func main() {

	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("Error: %+v\n%+v", err, string(debug.Stack()))
		}
	}()

	flag.Parse()
	if serviceip != nil && *serviceip != "" {
		// Verify the provided IP is the service. Send a query string to prevent an error in the log.
		resp, err := http.Get(fmt.Sprintf("http://%s:%s/", *serviceip, scan.DefaultServicePort))
		if err != nil {
			fmt.Printf("Error: error GETting service, error: %+v\n", err)
			os.Exit(exitCodeNoService)
		}
		app := resp.Header.Get(scan.ServiceHeader)
		if app != scan.ServiceAppName {
			fmt.Println("Error: The response was not from the appropriate service.")
			os.Exit(exitCodeWrongServer)
		}
		serviceurl = fmt.Sprintf("http://%s:%s/", *serviceip, scan.DefaultServicePort)
		fmt.Printf("\nService IP provided; serviceurl: %s\n", serviceurl)
	} else {
		fmt.Println("\nNo service IP provided; running standalone.")
	}

	fmt.Println("help is available by entering '?' at the prompt.")
	for {
		runCLI(os.Stdin)
	}
}

// execute runs the port scan directly, when the service is NOT being used to service requests.
func execute(port string, ips []string) {
	if port == "" {
		fmt.Println(scan.MissingPort)
		return
	} else if len(ips) == 0 {
		fmt.Println(scan.MissingIPs)
		return
	}

	results = scan.Scan(port, ips, threads, timeout)
}

// help dumps user help for the CLI.
func help() {
	fmt.Println("Portscanner, project home: https://github.com/paulfdunn/portscan")
	fmt.Println("An attempt is made to connect to connect to all specified IP addresses,")
	fmt.Println("using the specified port, using tcp network type. ")
	fmt.Println("Requests are asynchronous.")
	fmt.Println("")
	fmt.Println("See the README for general setup.")
	fmt.Println("Commands available:")
	fmt.Println("execute - executes a scan of provide IPs and port.")
	fmt.Println("results - dumps results output.")
	fmt.Println("setips - input a list of space separated IP addresses.")
	fmt.Println("setport - input a single port number.")
	fmt.Println("")
}

// getToService does the GET to the service when the service is being service requests
func getToService(qs string) {
	fmt.Printf("%s is being used to service this request.\n", scan.ServiceAppName)
	resp, err := http.Get(fmt.Sprintf("%s?%s", serviceurl, qs))
	if err != nil {
		fmt.Printf("ERROR: error GETting url: %s, error: %+v\n", qs, err)
		return
	}
	defer resp.Body.Close()

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if body == nil || err != nil {
		fmt.Printf("ERROR: getting body: %+v\n", err)
	}

	id := scan.ID{}
	json.Unmarshal(body, &id)
	if id.ID != "" {
		pendingResultID = id.ID
		return
	}

	if len(body) != 0 && strings.TrimSpace(string(body)) != "" {
		fmt.Printf("%s\n", body)
	}
	return
}

// runCLI runs the CLI. Call this in a forever loop.
func runCLI(ior io.Reader) {
	reader := bufio.NewReader(ior)
	fmt.Printf(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("ERROR: getting user input, error: %+v\n", err)
		return
	}
	input = strings.ToLower(strings.TrimSpace(input))
	inputs := strings.Split(input, " ")

	if len(inputs) == 0 || inputs[0] == "" {
		fmt.Println(noInput)
		return
	}

	cmd := strings.ToLower(inputs[0])
	var args []string
	if len(inputs) > 1 {
		args = inputs[1:]
	}
	switch cmd {
	case "execute":
		if serviceurl != "" {
			getToService(fmt.Sprintf("setips=%s&setport=%s", strings.Join(ips, ","), port))
		} else {
			execute(port, ips)
		}
	case "exit", "quit":
		os.Exit(0)
	case "results":
		if serviceurl != "" {
			getToService(fmt.Sprintf("results=%s", pendingResultID))
		} else {
			fmt.Printf("%s", results)
		}
	case "setips":
		results = scan.Results{}
		ips, err = scan.ValidateIPs(args, true)
		if err != nil {
			fmt.Printf("%+v\n", err)
		}
	case "setport":
		results = scan.Results{}
		if len(args) != 1 {
			fmt.Printf("%s\n", scan.InvalidPort)
			port = ""
		}
		port, err = scan.ValidatePort(args[0])
		if err != nil {
			fmt.Printf("%+v\n", err)
		}
	case "?":
		help()
	default:
		fmt.Printf("\nWARNING: Not a valid command:%s\n\n", inputs[0])
		help()
	}
}
