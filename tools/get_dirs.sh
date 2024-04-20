#!/bin/bash

# $1-domain; $2-wordlist; $3 output file; $4 - list extendtion
if [[ $# -eq 5 ]]
then
ffuf -u $1 -w $2 -o $3 -D -e $4 -mc 200,403,405,500,401,400 -ac -se

cat $3 | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP  "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2"    "$4"    "$6}' | sed 's/\"//g' >  /tmp/temp.json
mv /tmp/temp.json $3
fi
