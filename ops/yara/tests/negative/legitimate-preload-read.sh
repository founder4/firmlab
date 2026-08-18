#!/bin/sh
test -r /etc/ld.so.preload && sed -n '1,20p' /etc/ld.so.preload
