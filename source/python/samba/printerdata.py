#!/usr/bin/env python

#
# A python module that maps printerdata to a dictionary.  We define
# two classes.  The printerdata class maps to Get/Set/Enum/DeletePrinterData
# and the printerdata_ex class maps to Get/Set/Enum/DeletePrinterDataEx
#

#
# TODO:
#
#   - Implement __delitem__
#

from samba import spoolss

class printerdata:
    def __init__(self, host, creds = {}):
        self.hnd = spoolss.openprinter(host, creds = creds)

    def keys(self):
        return self.hnd.enumprinterdata().keys()

    def __getitem__(self, key):
        return self.hnd.getprinterdata(key)['data']

    def __setitem__(self, key, value):
        # Store as REG_BINARY for now
        self.hnd.setprinterdata({"key": "", "value": key, "type": 3,
                                 "data": value})
        
class printerdata_ex:
    def __init__(self, host):
        self.host = host
        self.top_level_keys = ["PrinterDriverData", "DsSpooler", "DsDriver",
                               "DsUser"]

    def keys(self):
        return self.top_level_keys

    def has_key(self, key):
        for k in self.top_level_keys:
            if k == key:
                return 1
        return 0

    class printerdata_ex_subkey:
        def __init__(self, host, key):
            self.hnd = spoolss.openprinter(host)
            self.key = key

        def keys(self):
            return self.hnd.enumprinterdataex(self.key).keys()

        def __getitem__(self, key):
            return self.hnd.getprinterdataex(self.key, key)['data']

    def __getitem__(self, key):
        return self.printerdata_ex_subkey(self.host, key)
