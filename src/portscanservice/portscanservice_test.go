package main

//
// TESTING IS MINIMAL
// For a take home test (interview) I consider the task to show I can code, and know
// test the test pattern. I did not create a full produciton app or associated tests.
//

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"portscan/src/scan"
	"testing"
	"time"
)

// TestQueryParams validates that any bad combination of query parameters does return bad status.
func TestQueryParams(t *testing.T) {
	timeout = time.Duration(100) * time.Millisecond
	ts := httptest.NewServer(http.HandlerFunc(handlerIndex))
	defer ts.Close()
	badQueries := []string{
		"?results=&setips=",
		"?results=&setports=",
		"?results=&setips=&setports=",
		"?setports=",
		"?setips="}
	for i := range badQueries {
		resp, err := http.Get(ts.URL + badQueries[i])
		if resp.StatusCode < http.StatusBadRequest {
			t.Errorf("Non-error status code received for bad query: %s\n, status: %d, error: %+v",
				badQueries[i], resp.StatusCode, err)
		}
	}
}

type testInput struct {
	ips               string
	port              string
	goodStatusScan    bool
	goodStatusResults bool
	expectedResults   []scan.Result
}

// Minimal test to verify that IPs and port are parsed and expected results returned.
// Does not test IPV6, CSV with a bad IP in the middle of a string of good IPS.
// Does not run a server and validate good responses.
// Does not validate deleting results or depth of queue.
func TestIPsAndPorts(t *testing.T) {
	timeout = time.Duration(100) * time.Millisecond
	ts := httptest.NewServer(http.HandlerFunc(handlerIndex))
	defer ts.Close()

	r1s := "dial tcp 127.0.0.1:65535: connect: connection refused"
	r1 := []scan.Result{{IP: "127.0.0.1", Port: "65535", Error: &r1s}}
	r3s := "dial tcp 127.0.0.1:4430: connect: connection refused"
	r3 := []scan.Result{{IP: "127.0.0.1", Port: "4430", Error: &r3s}}
	r4s1 := "dial tcp 127.0.0.1:4430: connect: connection refused"
	r4s2 := "dial tcp 8.8.8.8:4430: i/o timeout"
	r4 := []scan.Result{{IP: "127.0.0.1", Port: "4430", Error: &r4s1},
		{IP: "8.8.8.8", Port: "4430", Error: &r4s2}}
	inputs := []testInput{
		{"127.0.0.1", "-1", false, false, nil},
		{"127.0.0.1", "65535", true, true, r1},
		{"127.0.0.1", "65536", false, false, nil},
		{"127.0.0.1", "4430", true, true, r3},
		{"127.0.0.1,8.8.8.8", "4430", true, true, r4},
		{"1.2.3.4.5", "4430", false, false, nil},
	}
	for i := range inputs {
		fmt.Printf("\nTEST LOOP: %d\n", i)
		resp, err := http.Get(ts.URL + fmt.Sprintf("?setips=%s&setport=%s", inputs[i].ips, inputs[i].port))
		if (resp.StatusCode >= http.StatusBadRequest && inputs[i].goodStatusScan) ||
			(resp.StatusCode < http.StatusBadRequest && !inputs[i].goodStatusScan) {
			t.Errorf("Error from get, error: %+v\n", err)
		} else {
			fmt.Printf("%+v test case passed; status: %d\n", inputs[i], resp.StatusCode)
			if !inputs[i].goodStatusScan {
				fmt.Println("Continuing....")
			}

			defer resp.Body.Close()

			var body []byte
			body, err = ioutil.ReadAll(resp.Body)
			if body == nil || err != nil {
				fmt.Printf("Error getting body: %+v\n", err)
			}

			id := scan.ID{}
			time.Sleep(timeout)
			time.Sleep(time.Duration(100) * time.Millisecond)
			json.Unmarshal(body, &id)
			fmt.Printf("ID: %+v\n", id)
			resp, err := http.Get(ts.URL + fmt.Sprintf("?results=%s", id.ID))
			if err != nil {
				t.Errorf("Test failed: %+v", err)
			}

			if (resp.StatusCode >= http.StatusBadRequest && inputs[i].goodStatusResults) ||
				(resp.StatusCode < http.StatusBadRequest && !inputs[i].goodStatusResults) {
				t.Errorf("Incorrect status for results: %+v", inputs[i])
				continue
			}

			if resp.StatusCode >= http.StatusBadRequest {
				fmt.Println("Continue...")
				continue
			}

			body, err = ioutil.ReadAll(resp.Body)
			if body == nil || err != nil {
				fmt.Printf("Error getting body: %+v\n", err)
			}

			expct, _ := json.Marshal(inputs[i].expectedResults)
			if string(body) != string(expct) {
				t.Errorf("Unexpected results: %s", body)
			}
		}
	}
}
