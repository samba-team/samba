#
# A python module that maps printerdata to a dictionary.  We define
# two classes.  The printerdata class maps to Get/Set/Enum/DeletePrinterData
# and the printerdata_ex class maps to Get/Set/Enum/DeletePrinterDataEx
#

import spoolss

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
        
