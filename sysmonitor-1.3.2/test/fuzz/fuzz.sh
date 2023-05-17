#!/bin/bash

FUZZ_OPTION="corpus -dict=./dict/sysmonitor_fuzz.dict -runs=10000000 -max_total_time=3600 -rss_limit_mb=0"

# compile fuzz
make -j

# run fuzz
./sysmonitor_fuzz $FUZZ_OPTION -artifact_prefix=sysmonitor_fuzz-

# find crash file
echo "############# Fuzz Result #############"
crash=`find -name "*-crash-*"`
if [ x"$crash" != x"" ]; then
    echo "find bugs while fuzzing, pls check <*-crash-*> file"
    find -name "*-crash-*"
    exit 1
else
    echo "all fuzz success."
fi

