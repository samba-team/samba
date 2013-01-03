#!/bin/sh

echo "Pstree output for the hung script:"
pstree -p -a $1
