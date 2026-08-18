#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
printf '%s\n' "$QUERY_STRING"
