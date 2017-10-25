#!/bin/bash

set -e
shopt -s nocaseglob

# Start TorGhost
cd /opt/torghost
python torghost start

test -z ${EW_TIMEOUT+w} && EW_TIMEOUT=30
test -z ${EW_MAX_RETRIES+w} && EW_MAX_RETRIES=3
echo "Using environment variables:"
echo "TIMEOUT=$EW_TIMEOUT"
echo "MAX_RETRIES=$EW_MAX_RETRIES"

# Do we have an argument passed via the command line?
if [ -z ${1+x} ]; then
	URLFILE=urls.txt
	echo "No URL file defined, search for XLS files"
	ls /data/*.xlsx >/dev/null
	if [ "$?" != "0" ]; then
		echo "No XLSX input file to process"
		exit 1
	else
		/opt/xlsxtract.py -w 'New Today' -c A -r 2- -s /data/*.xlsx >/data/$URLFILE
	fi
else
	URLFILE=`basename "$1"`
	if [ ! -r "/data/$URLFILE" ]; then
		echo "Cannot read URLS from $URLFILE"
		exit 1
	fi
fi

echo "Found Onion URLs to process:"
cat "/data/$URLFILE"

# Remove previous results if exist
test -d /data/resuts && rm -r /data/results

cd /opt/EyeWitness
python EyeWitness.py -d /data/results -f "/data/$URLFILE" --headless --no-prompt --timeout $EW_TIMEOUT --max-retries $EW_MAX_RETRIES
mv /data/results /data/results-`date +"%Y%m%d%H%M%S"`
