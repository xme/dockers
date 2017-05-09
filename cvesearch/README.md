Introduction
============
Docker file to run cve-search (https://github.com/cve-search/cve-search)
Based on https://github.com/znb/Docker/tree/master/CVE-Search
The web interface is binding to 0.0.0.0:5000

Build
=====
$ docker built -t cvesearch:latest Dockerfile .

Usage
=====
$ docker run cvesearch:latest -p 5000:5000

Or use the docker compose file:

$ docker-compose run
