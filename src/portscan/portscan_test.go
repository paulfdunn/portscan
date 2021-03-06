package main

//
// TESTING IS MINIMAL
// For a take home test (interview) I consider the task to show I can code, and know
// test the test pattern. I did not create a full production app or associated tests.
//

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/paulfdunn/portscan/src/scan"
)

var (
	response = fmt.Sprintf(" - %s\n", appName)
)

type IPTest struct {
	ips             string
	port            string
	expectedResults int
	expectedErrors  int
}

// TestExecute feeds input to the CLI and validates results.
// scan() is implicitly tested here.
func TestExecute(t *testing.T) {
	fmt.Println("TestExecute start")
	var inputSource *bytes.Buffer
	ipTest := []IPTest{
		{"127.0.0.1", "9999", 1, 1},
		{"8.8.8.8", "443", 1, 0},
		{"::1", "9999", 1, 1},
		{"127.0.0.1 ::1", "9999", 2, 2}}
	for _, v := range ipTest {
		inputSource = bytes.NewBuffer([]byte(fmt.Sprintf("setport %s\n", v.port)))
		runCLI(inputSource)
		inputSource = bytes.NewBuffer([]byte("setips " + v.ips + "\n"))
		runCLI(inputSource)
		inputSource = bytes.NewBuffer([]byte("execute\n"))
		runCLI(inputSource)
		inputSource = bytes.NewBuffer([]byte("results\n"))
		runCLI(inputSource)

		errors := 0
		for j := 0; j < len(results); j++ {
			if results[j].Error != nil && *results[j].Error != scan.NoError {
				errors++
			}
		}
		if len(results) != v.expectedResults || errors != v.expectedErrors {
			t.Errorf("Unexpected scan results for IPs: %s, results: %+v", v.ips, results)
		}
	}
	fmt.Println("TestExecute done")
}
