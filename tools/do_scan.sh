#!/bin/bash




scan_urls=$1
vulnerability_result_path=$2

function nuclei()
{

        ~/go/bin/nuclei -t /root/nuclei-templates/cves/ -l /usr/src/app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 100 -severity critical,High
        sleep 1
        ~/go/bin/nuclei -t /root/nuclei-templates/vulnerabilities/ -l /usr/src/app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 100 -severity critical,High
        sleep 1
        ~/go/bin/nuclei -t /root/nuclei-templates/security-misconfiguration/ -l /usr/src/app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 50 -severity critical,High
        cat $RESULT_PATH/*.txt >> $RESULT_PATH/nuclei-summary-results.txt
        
        # $GO_PATH/go/bin/nuclei -t /root/nuclei-templates/cves/ -l /app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 100 -severity critical,High
        # sleep 1
        # $GO_PATH/go/bin/nuclei -t /root/nuclei-templates/vulnerabilities/ -l /app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 100 -severity critical,High
        # sleep 1
        # $GO_PATH/go/bin/nuclei -t /root/nuclei-templates/security-misconfiguration/ -l /app/$TARGET -o $RESULT_PATH/nuclei.$(date +%F_%H-%M-%S).txt -c 50 -severity critical,High
        # cat $RESULT_PATH/*.txt >> $RESULT_PATH/nuclei-summary-results.txt
}


function jaeles()
{
        ~/go/bin/jaeles scan -s "/root/pro-signatures-2021/critical-poc/.*" -U /usr/src/app/$TARGET -o $RESULT_PATH -c 100

        # $GO_PATH/go/bin/jaeles scan -s "/root/pro-signatures-2021/critical-poc/.*" -U /app/$TARGET -o $RESULT_PATH -c 100
        # sleep 1
        # $GO_PATH/jaeles scan -s /root/signatures-pro-2020/custom_signatures/files-sensitive/.* -U /app/$TARGET -o $RESULT_PATH -c 100
        # sleep 1
        # $GO_PATH/jaeles scan -s /root/signatures-pro-2020/pro-signatures/sensitive/.* -U /app/$TARGET -o $RESULT_PATH -c 100
        # sleep 1
        # $GO_PATH/jaeles scan -s /root/signatures-pro-2020/pro-signatures/products/.* -U /app/$TARGET -o $RESULT_PATH -c 100

}

jaeles
sleep 2
nuclei
