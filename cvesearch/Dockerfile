FROM ubuntu
MAINTAINER Matt Erasmus <code@zonbi.org>
RUN apt-get update
RUN apt-get install -yq git python3-pip python3-pymongo mongodb libxml2-dev python3-lxml redis-server tmux
RUN git clone https://github.com/cve-search/cve-search.git /opt/cve-search
WORKDIR /opt/cve-search
RUN pip3 install -r requirements.txt
WORKDIR /opt/cve-search/etc
RUN cp configuration.ini.sample configuration.ini
RUN sed -i 's/Host: 127.0.0.1/Host: 0.0.0.0/' configuration.ini
WORKDIR /root
COPY init.sh /root/init.sh
RUN chmod 700 /root/init.sh
RUN touch /.firstboot
EXPOSE 5000
CMD ["/root/init.sh"]