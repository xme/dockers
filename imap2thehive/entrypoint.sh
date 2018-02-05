#!/bin/bash
set -e
if [ -r /.firstboot ]; then
        # Enable logrotate
        cat <<__LOGROTATE__ >/etc/cron.daily/logrotate
#!/bin/sh
test -x /usr/sbin/logrotate || exit 0
/usr/sbin/logrotate /opt/logrotate.conf
__LOGROTATE__

        cat <<__LOGROTATE2__ >/opt/logrotate.conf
/var/log/cron.log
{
        rotate 7
        daily
        missingok
        notifempty
        delaycompress
        compress
}
__LOGROTATE2__
        chmod 0755 /etc/cron.daily/logrotate
        rm /.firstboot
fi

if [ ! -r /etc/imap2thehive.conf ]; then
    echo "[ERROR] Cannot read /etc/imap2thehive.conf. Volume not defined?"
    exit 1
fi
echo "Imap2TheHive polling started..."
/usr/sbin/cron && tail -F /var/log/cron.log
