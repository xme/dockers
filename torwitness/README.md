Introduction
============
Docker file to run Tor+EyeWitness. EyeWitness (https://github.com/ChrisTruncer/EyeWitness) is a tool to collect screenshots of websites.
The idea of the docker came after reading Micah Hoffman's blog post to browse new Onion website (https://webbreacher.com/2017/09/02/dark-web-report-torghost-eyewitness-goodness/). The docker has been created to extract Onion URL's from daily XLS files provided by @hunchy (https://twitter.com/hunchly/)

Build
=====
$ docker built -t torwitness/latest Dockerfile .

Usage
=====
$ docker run \	
	--run \
	-it \
	-v /local_path:/data \
	--cap-add=NET_ADMIN --cap-add=NET_RAW \
	--env EW_TIMEOUT=30 \
	--env EW_MAX_RETRIES=5 \
	torwitness \
	urls.txt

'urls.txt' is the text file with all the URLs that you want to visit through Tor/EyeWitness. This file must be available in the docker volume (/local_path/urls.txt). If you don't provide this file, the docker will search for .xlsx files in /data and extract URLs via my xlsxtract.py tool (https://github.com/xme/toolbox/blob/master/xlsxtract.py). The xlsx are expected to be the one provided by @hunchy. The results are stored in /data/results-YYYYMMDDHHMMSS/

WARNING: This Docker cannot be considered as safe because it has full access to the host network. This is required by torghost to properly intercept the HTTP traffic.

Example
=======
$ cat $HOME/torwitness/urls.txt
https://blog.rootshell.be
https://isc.sans.edu
$ docker run --rm -it -v $HOME/torwitness:/data --cap-add=NET_ADMIN --cap-add=NET_RAW torwitness urls.txt
```
      _____           ____ _               _
     |_   _|__  _ __ / ___| |__   ___  ___| |_
       | |/ _ \| '__| |  _| '_ \ / _ \/ __| __|
       | | (_) | |  | |_| | | | | (_) \__ \ |_
       |_|\___/|_|   \____|_| |_|\___/|___/\__|
	v2.0 - SusmithHCK | www.khromozome.com


[done]
[12:19:18] Configuring DNS resolv.conf file..  [done]
 * Starting tor daemon...                                                                                                                                                                                [ OK ]
[12:19:18] Starting tor service..  [done]
[12:19:19] setting up iptables rules [done]
[12:19:19] Fetching current IP...
[12:19:19] CURRENT IP : 51.15.79.107
Using environment variables:
TIMEOUT=30
MAX_RETRIES=3
Found Onion URLs to process:
https://blog.rootshell.be
https://isc.sans.edu
################################################################################
#                                  EyeWitness                                  #
################################################################################

Starting Web Requests (2 Hosts)
Attempting to screenshot https://blog.rootshell.be
Attempting to screenshot https://isc.sans.edu
Attempting to screenshot https://blog.rootshell.be
Attempting to screenshot https://isc.sans.edu
Finished in 22.2635469437 seconds
$ cd $HOME/torwitness
$ ls
results-20171025113745 urls.txt
$ cd results-20171025113745
$ firefox result.html
```
