FROM phusion/baseimage
MAINTAINER Xavier Mertens <xavier@rootshell.be>

RUN apt-get update && \
    apt-get install -y git wget sudo iptables python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Install xlsxtract
RUN pip3 install openpyxl
RUN wget https://raw.githubusercontent.com/xme/toolbox/master/xlsxtract.py && \
    chmod a+x /opt/xlsxtract.py

RUN git clone https://github.com/ChrisTruncer/EyeWitness.git

WORKDIR /opt/EyeWitness

RUN cd setup && \
    ./setup.sh

WORKDIR /opt
RUN git clone https://github.com/susmithHCK/torghost.git
WORKDIR /opt/torghost
RUN chmod 0755 install.sh && \
    ./install.sh

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

VOLUME /data

ENTRYPOINT ["/entrypoint.sh"]
