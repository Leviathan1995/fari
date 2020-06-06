#!/bin/bash

if [ "$1" = "client" ]
then
  sudo mkdir -p /root/proxy/
  sudo cp fari-client.service /etc/systemd/system/
  sudo cp fari-client /root/proxy/
  sudo cp .client.json /root/proxy/
  systemctl enable fari-client
  systemctl start fari-client
  systemctl status fari-client -l
elif [ "$1" = "server" ]
then
  sudo mkdir -p /root/proxy/
  sudo cp fari-server.service /etc/systemd/system/
  sudo cp fari-server /root/proxy/
  sudo cp .server.json /root/proxy/
  systemctl enable fari-server
  systemctl start fari-server
  systemctl status fari-server -l
else
  echo "Invalid parameter"
fi
