#
# Dockerfile to build a "DSS" container (Didier Stevens's Suite)
#
# @author:        Xavier Mertens <xavier@rootshell.be>
# @copyright:     AGPLv3 (http://www.gnu.org/licenses/agpl.html)
#

FROM ubuntu:16.04
MAINTAINER Xavier Mertens <xavier@rootshell.be>

ENV VERSION 1.1

RUN apt-get update && \
  apt-get upgrade -y && \
  apt-get install -y python-pip git figlet && \
  rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/DidierStevens/DidierStevensSuite /usr/local/bin
RUN chmod a+x /usr/local/bin/*
RUN pip install olefile

RUN echo "#!/bin/bash" >/entrypoint.sh
RUN echo "test \"\$1\" == \"/bin/bash\" && figlet \"DSSuite\" && echo Version $VERSION - Help: https://blog.didierstevens.com/my-software/ && echo" >>/entrypoint.sh
RUN echo 'exec $@' >>/entrypoint.sh
RUN chmod a+x /entrypoint.sh

VOLUME ["/malware"]
WORKDIR /malware

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
