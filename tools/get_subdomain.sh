#!/bin/bash

# $1 threads, $2 domain, $3 output directory, $4 amass active recon wordlist
for i in "$@" ; do
    if [[ $i == "sublist3r" ]] ; then
        python3 /usr/src/app/tools/Sublist3r/sublist3r.py -d $2 -t $1 -o $3/from_sublister.txt
    fi
    if [[ $i == "amass-passive" || $i == "amass" ]] ; then
        /usr/src/app/tools/amass enum --passive -d $2 -o $3/fromamass.txt
    fi
    if [[ $i == "amass-active" ]] ; then
        /usr/src/app/tools/amass enum -active -o $3/fromamass-active.txt -d $2 -brute -w $4 -config $5
    fi
    if [[ $i == "assetfinder" ]] ; then
        assetfinder --subs-only $2 > $3/fromassetfinder.txt
    fi
    if [[ $i == "subfinder" ]] ; then
        subfinder -d $2 -t $1 > $3/fromsubfinder.txt
    fi
done

aiodnsbrute -w $4 -r /usr/src/app/google.txt  -t 3000 -f $3/from_aiodns.csv -o csv $2 --no-verify
sleep 2
cat $3/from_aiodns.csv| awk -F "," '{print $1}' > $3/from_aiodns.txt

cat $3/*.txt > $3/subdomain_collection.txt
rm -rf $3/from*
sort -u $3/subdomain_collection.txt -o $3/sorted_subdomain_collection.txt
rm -rf $3/subdomain*
