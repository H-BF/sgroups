#!/bin/bash
chmod 744 /opt/swarm/etc/to-nft/flush.sh
mv /opt/swarm/etc/to-nft/hbf-agent-log /etc/logrotate.d/hbf-agent-log
chmod 644 /etc/logrotate.d/hbf-agent-log
mv /opt/swarm/etc/to-nft/hbf-agent.service /etc/systemd/system/hbf-agent.service
chmod 644 /etc/systemd/system/hbf-agent.service
