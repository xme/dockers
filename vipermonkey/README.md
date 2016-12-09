Introduction
============
Docker file to run vipermonkey (https://github.com/decalage2/ViperMonkey) from a Docker

Build
=====
$ docker built -t vipermonkey/latest Dockerfile .

Usage
=====
$ docker run --run -v /local/path:/malware vipermonkey/latest [options] <maliciousfile> ...