#!/bin/bash

CVESEARCHDIR=/opt/cve-search

echo "Starting services..."
echo
service mongodb start
service redis-server start
echo
if [ -r /.firstboot ]; then
        echo "Initializing Databases... (Please note this will take a while)"
        echo
        cd ${CVESEARCHDIR}/sbin
        ./db_mgmt.py -p
        ./db_mgmt_cpe_dictionary.py
        ./db_updater.py -c
        rm /.firstboot
fi
echo
python3 /opt/cve-search/web/index.py