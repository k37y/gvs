# Golang Vulnerability Scanner (GVS)
Analyze your Golang-based repository for vulnerabilities

### Build and run
```
make
```
### Build and run as a container image
```
make image
```

### Request using Curl
```
$ curl --silent \
       --location \
       --request "POST" \
       --header "Content-Type: application/json" \
       --data '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18"}' \
       "https://<URL>:8082/scan" | jq .
```
