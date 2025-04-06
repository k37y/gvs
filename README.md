# Golang Vulnerability Scanner (GVS)
Analyze your Golang-based repository for vulnerabilities

### Usage
```
$ curl --silent \
       --location \
       --request "POST" \
       --header "Content-Type: application/json" \
       --data '{"repo": "https://github.com/openshift/metallb", "branch": "release-4.18"}' \
       "https://<URL>/scan" | jq .
```
