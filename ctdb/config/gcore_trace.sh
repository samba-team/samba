#!/bin/sh

gcore -o "/var/log/core" "$1" 2>&1 | logger -t "ctdb:gcore_trace"
