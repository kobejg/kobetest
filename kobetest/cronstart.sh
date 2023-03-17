#!/bin/bash
if [ -e /bin/systemctl ];then
        if [ -e /sys/fs/cgroup/systemd/system.slice/cron.service ];then
                systemctl restart cron
        else
                systemctl restart crond
        fi
else
        service cron restart
fi

exit 0
