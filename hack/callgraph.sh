#!/bin/bash

LIB=${1}

foo=()
while IFS= read -r line; do
  foo+=("$line")
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
for file in "${!foo[@]}"; do
  echo "${foo[$file]}"
  if ! callgraph -format=digraph ${foo[$file]} | digraph somepath command-line-arguments.main ${LIB} 2>&1 | grep -q "digraph:"; then
	  callgraph -format=digraph ${foo[$file]} | digraph somepath command-line-arguments.main ${LIB} | digraph to dot > /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
	  cat /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot | sfdp -T svg -o/tmp/gvs-cache/img/${LIB//[\/.]/-}-$file.svg -Goverlap=scale
	  rm /tmp/gvs-cache/${LIB//[\/.]/-}-$file.dot
  fi
done
