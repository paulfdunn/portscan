# portscan
This project was completed as part of the interview process with twilio; 2021/02/03.
This repository provides: a port scanning service running in a container that uses a ReST API, a standalone port scanning CLI application in another container, and a mode of the CLI where it uses the ReST API to run the port scan. GO developers can just build and run the CLI in standalone mode if they prefer to not use Docker containers.

See the Problem statement at the end of the document for more details.

The context of this repo is as a "take home test" for an interview. My take of the expectations is this: better than white board code, but less than a full production app. In particular, tests will be skipped, or minimal at best.
## Requirements
* You need to have docker (engine and compose) installed. This was tested with client 20.10.1 and server 19.03.13.
* The CLI can be run in a docker container, or built and run on your host. The later will require having GOLANG
installed and familiarity with building GO apps (tested with GO version 1.14.14).
## Install
Create a local directory in which to clone portscan, cd to that directory, and clone the repo.
```mkdir SOME_DIR; 
cd SOME_DIR; 
git clone https://github.com/paulfdunn/portscan.git
```
(Optional) If you get an error 'Got permission denied while trying to connect to the Docker daemon socket' running any docker related commands, look in this file for details regarding running as non-root user, and execute the script if necessary.
```
./dockersetup.sh
```
## Implementation note
The ReST API was coded to use only the GET method, with query strings. I did this to make it easier to use and test the API for the purpose of the take home test. This allows someone to even just use a browser to test the API. For a purely programmatic interface, I would have have used addtional methods and made the interface more ReSTful.
## Running the containers
```
# execute this from cloned portscan directory; cd into that directory if you are not there. 
docker-compose up -d
```
### Using the CLI
The following command:
```
docker-compose exec cli /bin/ash
```
Will leave you at a prompt in the CLI container:
```
/app # 
```
### CLI in standalone mode
To use the CLI in standalone mode (CLI itself does the port scanning). Use '?' for help. 
Example session:
```
/app # ./portscan 

No service IP provided; running standalone.
help is available by entering '?' at the prompt.
portscan>setips 8.8.8.8 9.9.9.9
portscan>setport 443
portscan>execute
portscan>results
IP:  8.8.8.8        | Port: 443  | Error: none
IP:  9.9.9.9        | Port: 443  | Error: none
portscan>exit
/app # 
```  
### CLI against the service
To use the CLI against the service, restart the CLI with the hostname of the service. Example session:
```
/app # ./portscan -serviceip=service

Service IP provided; serviceurl: http://service:8000/
help is available by entering '?' at the prompt.
portscan>setips 8.8.8.8 9.9.9.9
portscan>setport 443
portscan>execute
portscanservice is being used to service this request.
portscan>results
portscanservice is being used to service this request.
[{"IP":"8.8.8.8","Port":"443","Error":"none"},{"IP":"9.9.9.9","Port":"443","Error":"none"}]
portscan>exit
/app # an>
exit
```  
### CURL commands against the service
Run commands against the service directly using curl, **from the CLI terminal**. (Note the service is running on port 8000.) Also note the **curl payload is in single quotes**, otherwise the & are parsed by the shell.
Example session:
```
/app # curl -s 'http://service:8000/?setips=8.8.8.8,9.9.9.9&setport=443' | json_pp
{
   "ID" : "590e755a-e4ba-1727-5d63-765cc2303290"
}
/app # curl -s 'http://service:8000/?results=590e755a-e4ba-1727-5d63-765cc2303290' | json_pp
[
   {
      "Error" : "none",
      "IP" : "8.8.8.8",
      "Port" : "443"
   },
   {
      "Error" : "none",
      "IP" : "9.9.9.9",
      "Port" : "443"
   }
]
/app # curl  'http://service:8000/?results=590e755a-e4ba-1727-5d63-765cc2303290'
Error: ID 590e755a-e4ba-1727-5d63-765cc2303290 was not a recognized ID
/app # 
```
Notes:
* You can also execute curl commands from your host to the service, if you prefer. 'curl http://localhost:8000/'
* When using curl from the container, use the hostname of the service, which is 'service'. I.E. 'curl http://service:8000/'. But if you are not using the container, your host does not resolve the container hostname; use localhost. I.E. 'curl http://localhost:8000/'
* 'curl -s' is used to silence the curl output for data transfer information.
* json_pp is used to pretty print the output
* When using the service directly, the request command returns an ID that is used to subsequently request results. (The CLI is managing this for you.) Once results are fetched, they cannot be fetched again. And only the 30 most results results are kept. Both removing fetched results and limiting the result queue are done to make sure unfetched results dont result in a memory leak.
## Shutting down
If you have not already done so, exit the CLI container:
```
exit
```
Execute the following to stop the containers:
```
docker-compose down
``` 
# All below text was cut/paste from a PDF provided by Twilio.
## Problem
Complete a short programming assignment

* Complete the exercise detailed below.
* As mentioned above, please submit code written in Go, Python, or Ruby.
* Include instructions on how to run your program. Make sure that someone familiar with your chosen language can easily run your code.
* Include tests and instructions on how to run the tests.
* Share your code via a publicly accessible Git repository.

For this exercise, you will produce a simple server and CLI to interact with it. The build process
for the server application must produce a runnable Docker image.
Both can be implemented in the language of your choice. Golang is the most commonly used
language at Twilio SendGrid, but we are also able to review code in the following languages:
* Go
* Python
* Ruby

You must be able to demonstrate your server running in the docker container (or on your
kubernetes instance - see bonus) and your CLI successfully turning command line input into
server requests and displaying the response.

## Port scanner
* Build a simple port scanning server with a CLI to request a scan and fetch the results.
* The CLI should accept an arbitrary TCP port number and a list of IP addresses to scan.
* The port scan request should be asynchronous.
* The CLI should have separate options to request the scan and fetch the results from the server.

Note: You don't have to persist the results to disk -- it's okay if they're lost when the server exits.

## Bonus
Set up minikube or kind and deploy the server application to your local test cluster.