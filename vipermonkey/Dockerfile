FROM ubuntu:latest
MAINTAINER Xavier Mertens <xavier@rootshell.be>

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install wget unzip python-pip

WORKDIR /opt
RUN wget https://github.com/decalage2/ViperMonkey/archive/master.zip \
    && unzip master.zip

WORKDIR /opt/ViperMonkey-master
RUN pip install -U -r requirements.txt
RUN python setup.py install

WORKDIR /malware
ENTRYPOINT [ "/opt/ViperMonkey-master/vipermonkey/vmonkey.py" ]
CMD [ "-h" ]