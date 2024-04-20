#!/bin/bash
subdomain_file=$1
output_file=$2
function enumIP() {
	/usr/src/app/tools/massdns/bin/massdns -t A -o S -s 5000 -w $output_file/massdns.out -r /usr/src/app/google.txt --root $subdomain_file
	sleep 1
	cat $output_file/massdns.out|awk '{print $3}' |sort -u |uniq| grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|cf-check > $output_file/alive_ip.txt
	sleep 1
	cat $output_file/massdns.out | awk -F ". " '{print $1}' |sort -u > $output_file/alive_subdomain.txt

}
enumIP
