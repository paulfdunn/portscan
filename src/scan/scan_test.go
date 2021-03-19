package scan

//
// TESTING IS MINIMAL
// For a take home test (interview) I consider the task to show I can code, and know
// test the test pattern. I did not create a full production app or associated tests.
//

import (
	"fmt"
	"testing"
	"time"
)

// Scan is currently implicitly tested by tests in portscan.

const (
	threads = 10
	timeout = time.Duration(1) * time.Second
)

type IPTest struct {
	ips             []string
	port            string
	expectedResults int
	expectedErrors  int
}

// TestValidatePort tests the input parsing.
func TestValidatePort(t *testing.T) {
	// portMap is a map of port_number/should_pass pairs
	portMap := map[string]bool{"-1": false, "0": true, "65535": true, "65536": false}
	for k, v := range portMap {
		_, err := ValidatePort(k)
		if (err == nil && v == false) || (err != nil && v == true) {
			t.Errorf("Port %s was accepted!", k)
		}
	}
}

// TestValidateIPs tests the input parsing.
func TestValidateIPs(t *testing.T) {
	// ipMap is a map of ips/should_pass pairs
	ipMap := map[string]bool{"127.0.0.1": true, "1.2.3.4.5": false, "::1": true}
	for k, v := range ipMap {
		_, err := ValidateIPs([]string{k}, true)
		if (err == nil && v == false) || (err != nil && v == true) {
			t.Errorf("IP %s was accepted!", k)
		}
	}
}

// Scan has no validation; validation is supposed to be done in prior calls. So
// invalid IPs will error.
func TestScan(t *testing.T) {
	fmt.Println("TestExecute start")
	ipTest := []IPTest{
		{[]string{"127.0.0.1"}, "9999", 1, 1},
		{[]string{"8.8.8.8"}, "443", 1, 0},
		{[]string{"::1"}, "9999", 1, 1},
		{[]string{"127.0.0.1", "::1"}, "9999", 2, 2},
		{[]string{"127.0.0.1", "8.8.8.8"}, "9999", 2, 2}}
	for _, v := range ipTest {
		results := Scan(v.port, v.ips, threads, timeout)

		errors := 0
		for j := 0; j < len(results); j++ {
			if results[j].Error != nil && *results[j].Error != NoError {
				errors++
			}
		}
		if len(results) != v.expectedResults || errors != v.expectedErrors {
			t.Errorf("Unexpected scan results for IPs: %s, results: %+v", v.ips, results)
		}
	}
	fmt.Println("TestExecute done")
}
