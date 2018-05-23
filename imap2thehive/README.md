# Purpose
The script imap2thehive.py polls an IMAP4 mailbox for new emails and imports fetched messages into an instance of [TheHive](https://thehive-project.org/). By default, a new case is created per email read. If the subject of the mail contains "[ALERT]", an alert is created.

# Configuration
The script is fully configurable via a Python-friendly configuration file. See imap2thehive.conf sample for more details.

# Usage
The script can be run manually to import a mailbox or it can be scheduled to run at fixed interval with a cron job. The syntax is simple:
```
# ./imap2thehive.py -h
usage: imap2thehive.py [-h] [-v] [-c CONFIG]

Process an IMAP folder to create TheHive alerts/cased.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -c CONFIG, --config CONFIG
                        configuration file (default: /etc/imap2thehive.conf)
```

# Docker Container
I created a Dockerfile to build a container:

```
# git clone https://github.com/xme/dockers
# cd imap2thehive
# docker build -t imap2thehive:latest .
# docker run -v $PWD/imap2thehive.conf:/etc/imap2thehive.conf:ro imap2thehive
```

# Observables Whitelisting
The script is able to extract observables (emails, URLs, files, hashes). To avoid too many false positives, it is possible to create whitelists (based on regular expressions). See the file imap2thehive.whitelists.