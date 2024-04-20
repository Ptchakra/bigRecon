#!/bin/bash

url=$1
signature=$2
result_path=$3
jaeles config init
jaeles config add --signDir $NGINE_HOME/tools/jaeles/signatures/
jaeles config add --signDir $NGINE_HOME/signature/static/
jaeles scan -s $2 -u $1 -o $3 --debug
