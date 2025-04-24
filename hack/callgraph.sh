#!/bin/bash

# Usage
# bash hack/callgraph.sh CVE-2023-52081 ~/code/src/github.com/k37y/metallb

CVE=${1}
DIR=${2}
files=()

ID=$(curl -s "https://vuln.go.dev/index/vulns.json" | jq -r --arg cve "$CVE" '.[] | select(.aliases != null and (.aliases[] == $cve)) | .id')

if [ -z "${ID}" ]; then
 echo "No GO ID found"
 exit 1
else
 echo "${ID}"
fi

pushd ${DIR} > /dev/null

while IFS= read -r line; do
  files+=("$line")
done < <(
  go list -f '{{.Name}}: {{.Dir}}' ./... | grep '^main' | cut -f2 -d: |
  while read -r dir; do
    for f in "$dir"/*.go; do
      [[ "$f" == *_test.go ]] && continue
      rel=$(realpath --relative-to="$(pwd)" "$f")
      rel_dir=$(dirname "$rel")
      echo "$rel_dir:$rel"
    done
  done | awk -F: '{files[$1]=(files[$1] ? files[$1] " " : "") $2} END {for (d in files) print files[d]}'
)

rm -rf /tmp/gvs-cache/img && mkdir /tmp/gvs-cache/img

# Print the array contents properly
for file in "${!files[@]}"; do
  while read LIB; do
  echo "Scanning ${LIB} using ${files[$file]} ..."
  if ! callgraph -format=digraph ${files[$file]} | digraph somepath command-line-arguments.main ${LIB} 2>&1 | grep -q "digraph:"; then
	  callgraph -format=digraph ${files[$file]} | digraph somepath command-line-arguments.main ${LIB} | digraph to dot > /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
	  cat /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot | sfdp -T svg -o/tmp/gvs-cache/img/${LIB//[\/.]/-}-$file.svg -Goverlap=scale
	  echo "Found usage!"
	  echo "Generated /tmp/gvs-cache/img/${LIB//[\/.]/-}-$file.svg"
	  rm /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
  fi
  done < <(curl -sL "https://vuln.go.dev/ID/${ID}.json" | \
jq -r '.affected[] | select(.ecosystem_specific.imports != null) | .ecosystem_specific.imports[] | [.path as $p | .symbols[] | "\($p).\(.)"] | .[]' | \
while read -r line; do
  echo "$line"
  prefix="${line%.*}"    # everything before the last dot
  suffix="${line##*.}"   # everything after the last dot
  echo "(${prefix}).${suffix}"
  echo "(*${prefix}).${suffix}"
done)
done

pushd > /dev/null

echo "Scanning completed!"
