#!/bin/sh
wget https://updates.invalid/device/image.bin -O /var/cache/image.bin
sha256sum -c /etc/vendor/image.sha256
