#!/bin/bash

# Usage
# bash hack/callgraph.sh CVE-2023-52081 ~/code/src/github.com/k37y/metallb

CVE=${1}
DIR=${2}
files=()

version_ge() {
  semver "$@"
}

ID=$(curl -s "https://vuln.go.dev/index/vulns.json" | jq -r --arg cve "$CVE" '.[] | select(.aliases != null and (.aliases[] == $cve)) | .id')

if [ -z "${ID}" ]; then
	echo "No Go CVE ID found"
	exit 1
else
	echo "Go CVE ID found: <strong>${ID}</strong>"
	echo ""
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

mkdir -p /tmp/gvs-cache/img

for file in "${!files[@]}"; do
  while read LIB; do
	  echo "Finding usage of ${LIB}, starting from main(), using ${files[$file]} entry point file(s) ..."
	  if ! callgraph -format=digraph ${files[$file]} | digraph somepath command-line-arguments.main ${LIB} 2>&1 | grep -q "digraph:"; then
		  mkdir -p /tmp/gvs-cache/img/${CVE}-${DIR##*/}
		  echo ""
		  echo "Found usage: <strong>${LIB}</strong>"
		  # CURRENT_MOD_VERSION=$(go list -f '{{.Module.Path}}@{{.Module.Version}}' ${LIB%.*})
		  CURRENT_MOD_PATH=$(go list -f '{{.Module.Path}}' ${LIB%.*})
		  CURRENT_REPLACE_VERSION=$(go mod edit -json | jq -r --arg MOD "${CURRENT_MOD_PATH}" '.Replace[] | select(.Old.Path == $MOD) | "\(.New.Path)@\(.New.Version)"')
		  [[ -z "${CURRENT_REPLACE_VERSION}" ]] && CURRENT_MOD_VERSION=$(go list -f '{{.Module.Path}}@{{.Module.Version}}' "${LIB%.*}")
		  echo "Current version: <strong>${CURRENT_REPLACE_VERSION:-$CURRENT_MOD_VERSION}</strong>"
		  FIXED_MOD_VERSION=$(curl -sL "https://vuln.go.dev/ID/${ID}.json" | jq -r --arg lib "${CURRENT_MOD_PATH}" '.affected[] | select(.package.name == $lib) | .package.name + "@v" + (.ranges[] | select(.type == "SEMVER") | .events[] | select(.fixed != null) | .fixed)')
		  echo "Fixed version: <strong>${FIXED_MOD_VERSION}</strong>"
		  CMV=${CURRENT_MOD_VERSION##*@}
                  FMV=${FIXED_MOD_VERSION##*@}

                  if [[ $(version_ge "$CMV" "$FMV") == "yes" ]]; then
			  echo
			  echo "No action required"
			  echo
		  elif [[ -n "${CURRENT_REPLACE_VERSION}" ]]; then
			  echo
			  echo "Commands to fix it:"
			  echo "<strong>go mod edit -replace=${CURRENT_REPLACE_VERSION}=${FIXED_MOD_VERSION}</strong>"
			  echo "<strong>go mod tidy</strong>"
			  echo "<strong>go mod vendor</strong>"
			  echo
			  echo "Generating callgraph of ${LIB}, starting from main(), using ${files[$file]} entry point file(s) ..."
		          callgraph -format=digraph ${files[$file]} | digraph somepath command-line-arguments.main ${LIB} | digraph to dot > /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
		          cat /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot | sfdp -T svg -o/tmp/gvs-cache/img/${CVE}-${DIR##*/}/${LIB//[\/.]/-}-$file.svg -Goverlap=scale
		          rm /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
		  else
			  echo
                          echo "Commands to fix it:"
                          echo "<strong>go get ${FIXED_MOD_VERSION}</strong>"
                          echo "<strong>go mod tidy</strong>"
                          echo "<strong>go mod vendor</strong>"
                          echo
		          echo "Generating callgraph of ${LIB}, starting from main(), using ${files[$file]} entry point file(s) ..."
		          callgraph -format=digraph ${files[$file]} | digraph somepath command-line-arguments.main ${LIB} | digraph to dot > /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
		          cat /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot | sfdp -T svg -o/tmp/gvs-cache/img/${CVE}-${DIR##*/}/${LIB//[\/.]/-}-$file.svg -Goverlap=scale
		          rm /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
		  fi
	  fi
  done < <(curl -sL "https://vuln.go.dev/ID/${ID}.json" | \
jq -r '.affected[] | select(.ecosystem_specific.imports != null) | .ecosystem_specific.imports[] | [.path as $p | .symbols[] | "\($p).\(.)"] | .[]' | \
while read -r line; do
	echo "$line"
	prefix="${line%.*}"
	suffix="${line##*.}"
	echo "(${prefix}).${suffix}"
	echo "(*${prefix}).${suffix}"
done)
done

pushd > /dev/null
