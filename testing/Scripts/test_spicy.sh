#!/bin/bash

# set -e

dt=$(date +%Y-%m-%d-%H-%M-%S)

# LOGFILE=./$dt.log
LOGFILE=/home/george/testing_spicy_automat/$dt.log
echo $LOGFILE

dir=$1



function run_spicy {
    cd $dir

    # for FILE in $dir; 
    for FILE in *;
        do 
        echo $FILE >> $LOGFILE;
        cat $FILE | spicy-driver --debug /home/george/iec-104-zeek/spicy-iec104/analyzer/iec104.spicy;
    done
}

run_spicy 2>> ${LOGFILE}

# run_spicy $LOGFILE