#!/bin/bash

# run subdomain takeover check
# single thread because with multple thread the json is inconsistent TODO: multiple threads
subjack -w $1/alive.txt -t $2 -a -o $1/takeover_result.json --ssl -c /app/tools/subjack_fingerprint.json -v
