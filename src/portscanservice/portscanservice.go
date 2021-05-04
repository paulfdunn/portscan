// portscanservice is a service for port scanning using a ReST API.
// project home: https://github.com/paulfdunn/portscan
// Make GET requests with query keys 'setips' and 'setport' to run an asynchronous scan
// to all IPs and the designated port. Starting a scan will return an ID as JSON.
// Retrieve results with a query key 'results', and value of the ID returned from starting the scan.
// Results can be retrieved at any time after starting a scan, though a result may be
// incomplete until the timeout.
// To prevent memory growth in the event of unread results, resutls are kept in a queue
// and old results removed. Results may also only be read once, as the result is deleted
// when it is read.
// Query string keys: results, setips, setport
// Examples: (change 127.0.0.1 to the service IP when not running on the same host):
// curl http://127.0.0.1%s/?setips=8.8.8.8,9.9.9.9&setport=443
// curl http://127.0.0.1%s/?results=SOME_ID

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/paulfdunn/portscan/src/scan"
)

const (
	// HTTPPort is the port that this service is listening on for API requests.
	// TODO: Make this an input.
	HTTPPort = ":" + scan.DefaultServicePort

	// threads could be a user input, if desired; easy change.
	threads = 10

	cmdResults = "results"
	cmdSetips  = "setips"
	cmdSetport = "setport"

	resultsQueueSize = 30
)

var (
	// timeout is timeout for scan requests
	// TODO: Make this an input.
	timeoutSeconds = 2
	timeout        = time.Duration(timeoutSeconds) * time.Second

	help = []byte(
		"\n" +
			"portscanservice is a service for port scanning using a ReST API. " +
			"project home: https://github.com/paulfdunn/portscan\n" +
			"Make GET requests with query keys 'setips' and 'setport' to run an asynchronous scan " +
			"to all IPs and the designated port. Starting a scan will return an ID as JSON.\n" +
			"Retrieve results with a query key 'results', and value of the ID returned from starting the scan.\n" +
			"Results can be retrieved at any time after starting a scan, though all results may not be " +
			"available until the timeout.\n" +
			"Query string keys: results, setips, setport\n" +
			"Examples: (change 127.0.0.1 to the service IP when not running on the same host):\n" +
			fmt.Sprintf("curl http://127.0.0.1%s/?setips=8.8.8.8,9.9.9.9&setport=443\n", HTTPPort) +
			fmt.Sprintf("curl http://127.0.0.1%s/?results=SOME_ID\n", HTTPPort))

	resultsMap     map[string]scan.Results
	resultsMapLock sync.RWMutex
	resultsQueue   chan string
)

func init() {
	resultsMap = make(map[string]scan.Results)
	resultsQueue = make(chan string, resultsQueueSize)
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("ERROR: %+v\n%+v", err, string(debug.Stack()))
		}
	}()

	http.Handle("/", http.HandlerFunc(handlerIndex))

	fmt.Printf("INFO: %s starting HTTP server.\n", scan.ServiceAppName)
	httpServer := http.Server{
		Addr:           HTTPPort,
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}
	fmt.Println(httpServer.ListenAndServe())
}

// handlerIndex handles all ReST API requests.
func handlerIndex(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			msg := []byte(fmt.Sprintf("ERROR: %+v\n%s", err, string(debug.Stack())))
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("%+v", msg))
			return
		}
	}()

	// Always let callers know the responding app.
	w.Header().Set(scan.ServiceHeader, scan.ServiceAppName)

	ips, port, cmd, results, err := queryValidateAndParse(w, r)
	if err != nil {
		return
	}
	// fmt.Printf("Debug: %s, %s, %s, %+v, %+v\n", ips, port, cmd, results, err)

	if cmd == cmdResults {
		b, err := json.Marshal(results)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("%+v", fmt.Sprintf("ERROR: %+v", err)))
			return
		}

		fmt.Printf("%s: %+v", cmdResults, results)
		w.WriteHeader(http.StatusOK)
		w.Write(b)
		return
	}

	id, err := uniqueID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("%+v", fmt.Sprintf("ERROR: %+v", err)))
		return
	}
	go func(idin string) {
		rslts := scan.Scan(port, ips, threads, timeout)
		resultsQueue <- idin
		addResultRemoveOldest(idin, rslts)
	}(id)
	b, err := json.Marshal(scan.ID{ID: id})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("%+v", fmt.Sprintf("ERROR: %+v", err)))
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write(b)
}

// queryValidateAndParse validates the query string and returns the pertinent output.
func queryValidateAndParse(w http.ResponseWriter, r *http.Request) (ips []string,
	port string, cmd string, results scan.Results, err error) {
	// Make query parameters case insensitive.
	u, err := url.Parse(strings.ToLower(r.RequestURI))
	if err != nil {
		msg := fmt.Sprintf("ERROR:parsing URL, error: %+v\n\n%s", err, help)
		writeError(w, http.StatusBadRequest, msg)
		return nil, "", "", nil, err
	}

	qs := u.Query()
	ipsUser, ipsCmd := qs[cmdSetips]
	portUser, portCmd := qs[cmdSetport]
	resultsUser, resultsCmd := qs[cmdResults]

	if resultsCmd && (ipsCmd || portCmd) {
		err := fmt.Errorf("results must be requested separately from setting IPs and port")
		msg := fmt.Sprintf("ERROR: %+v\n\n%s", err, help)
		writeError(w, http.StatusBadRequest, msg)
		return nil, "", "", nil, err
	} else if !resultsCmd && !(ipsCmd && portCmd) {
		err := fmt.Errorf("the query must include ONLY the key '%s', or BOTH keys '%s' and '%s'",
			cmdResults, cmdSetips, cmdSetport)
		msg := fmt.Sprintf("ERROR: %+v\n\n%s", err, help)
		writeError(w, http.StatusBadRequest, msg)
		return nil, "", "", nil, err
	}

	if resultsCmd {
		if len(resultsUser) != 1 {
			err := fmt.Errorf("only one result can be requested at a time, received: %+v", resultsUser)
			msg := fmt.Sprintf("ERROR: %+v\n\n%s", err, help)
			writeError(w, http.StatusBadRequest, msg)
			return nil, "", "", nil, err
		}

		resultsMapLock.RLock()
		v, ok := resultsMap[resultsUser[0]]
		delete(resultsMap, resultsUser[0])
		resultsMapLock.RUnlock()
		if ok {
			return nil, "", cmdResults, v, nil
		}

		err := fmt.Errorf("ID %s was not a recognized ID", resultsUser[0])
		msg := fmt.Sprintf("ERROR: %+v\n", err)
		writeError(w, http.StatusBadRequest, msg)
		return nil, "", "", nil, err
	}

	if portCmd {
		if len(portUser) != 1 {
			err := fmt.Errorf("%s", scan.InvalidPort)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("%+v\n", err))
			return nil, "", "", nil, err
		}
		port, err = scan.ValidatePort(portUser[0])
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("%+v\n", err))
			return nil, "", "", nil, err
		}
	}

	if ipsCmd {
		for i := range ipsUser {
			ips = append(ips, strings.Split(ipsUser[i], ",")...)
		}
		ips, err = scan.ValidateIPs(ips, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("%+v\n", err))
			return nil, "", "", nil, err
		}
	}

	return ips, port, "", nil, err
}

// addResultRemoveOldest adds the specified results to the map of results. The oldest result
// is removed from the map of output results if there are >=resultsQueueSize results in the map.
func addResultRemoveOldest(id string, rslts scan.Results) {
	resultsMapLock.Lock()
	resultsMap[id] = rslts
	if len(resultsQueue) >= resultsQueueSize {
		oldestResult := <-resultsQueue
		delete(resultsMap, oldestResult)
	}
	resultsMapLock.Unlock()
}

// uniqueID generates unique IDs (UUIDs)
func uniqueID() (id string, err error) {
	idBin := make([]byte, 16)
	// rand is not initialized in this implementation; initialize rand if unique data per run
	// is required.
	_, err = rand.Read(idBin)
	if err != nil {
		err := fmt.Errorf("creating unique binary ID, error: %+v", err)
		fmt.Printf("ERROR: %+v", err)
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", idBin[0:4], idBin[4:6], idBin[6:8], idBin[8:10], idBin[10:]), err
}

// writeError writes an error to the ResponseWriter.
func writeError(w http.ResponseWriter, status int, msg string) {
	fmt.Printf("%s", msg)
	w.WriteHeader(status)
	w.Write([]byte(msg))
}
