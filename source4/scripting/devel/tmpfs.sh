#!/bin/bash

# This sets up bin/ and st/ as tmpfs filesystems, which saves a lot of
# time waiting on the disk!

rm -rf bin st
mkdir -p bin st || exit 1
sudo mount -t tmpfs /dev/null bin || exit 1
sudo chown $USER bin || exit 1
echo "tmpfs setup for bin/"
sudo mount -t tmpfs /dev/null st || exit 1
sudo chown $USER st || exit 1
echo "tmpfs setup for st/"
