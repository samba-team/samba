#!/usr/bin/env python
#
# Display information on all printers on a print server
#

import sys, spoolss

if len(sys.argv) != 2:
    print "Usage: changeid.py <printername>"
    sys.exit(1)

printserver = sys.argv[1]

# Get list of printers

try:
    printer_list = spoolss.enumprinters(printserver)
except:
    print "error enumerating printers on %s" % printserver
    sys.exit(1)

# Display basic info

for printer in printer_list:
    print "%s: %s" % (printer["printer_name"], printer["comment"])
