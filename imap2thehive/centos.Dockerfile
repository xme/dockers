FROM centos:7
MAINTAINER Axel Gocan <axel.gocan@protonmail.com>

RUN yum update && \
    yum install -y gcc python3 crontabs python3-devel python3-pip cron logrotate && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
COPY requirements.txt .
RUN pip3 install -r requirements.txt

WORKDIR /etc
COPY imap2thehive.conf .

WORKDIR /opt
COPY imap2thehive.py .
COPY imap2thehive.whitelists . 

# Create the cronjob
# An empty line is mandatory!
RUN echo '*/5 * * * * root (/opt/imap2thehive.py -c /etc/imap2thehive.conf -v >>/var/log/cron.log 2>&1)' >>/etc/crontab
RUN echo '' >>/etc/crontab
RUN touch /var/log/cron.log
RUN touch /.firstboot
COPY entrypoint.sh .
RUN chmod 0755 /opt/entrypoint.sh

ENTRYPOINT [ "/opt/entrypoint.sh" ]
