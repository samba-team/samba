import string
import dcerpc

def test_OpenPrinterEx(pipe, printer):

    print 'testing spoolss_OpenPrinterEx(%s)' % printer

    r = {}
    r['printername'] = '\\\\win2k3dc\\%s' % printer
    r['datatype'] = None
    r['devmode_ctr'] = {}
    r['devmode_ctr']['size'] = 0
    r['devmode_ctr']['devmode'] = None
    r['access_mask'] = 0x02000000
    r['level'] = 1
    r['userlevel'] = {}
    r['userlevel']['level1'] = {}
    r['userlevel']['level1']['size'] = 0
    r['userlevel']['level1']['client'] = None
    r['userlevel']['level1']['user'] = None
    r['userlevel']['level1']['build'] = 1381
    r['userlevel']['level1']['major'] = 2
    r['userlevel']['level1']['minor'] = 0
    r['userlevel']['level1']['processor'] = 0

    result = dcerpc.spoolss_OpenPrinterEx(pipe, r)

    return result['handle']


def test_ClosePrinter(pipe, handle):

    r = {}
    r['handle'] = handle

    dcerpc.spoolss_ClosePrinter(pipe, r)


def test_EnumPrinters(pipe):

    print 'testing spoolss_EnumPrinters'

    printer_names = None

    r = {}
    r['flags'] = 0x02
    r['server'] = None

    for level in [1, 2, 4, 5]:

        r['level'] = level
        r['buf_size'] = 0
        r['buffer'] = None

        result = dcerpc.spoolss_EnumPrinters(pipe, r)

        if result['result'] == dcerpc.WERR_INSUFFICIENT_BUFFER:
            r['buffer'] = result['buf_size'] * '\x00'
            r['buf_size'] = result['buf_size']

            result = dcerpc.spoolss_EnumPrinters(pipe, r)

        printers = dcerpc.unmarshall_spoolss_PrinterInfo_array(
            result['buffer'], r['level'], result['count'])

        if printer_names is None:
            printer_names = map(
                lambda x: string.split(x['info1']['name'], ',')[0], printers)

    for printer in printer_names:

        handle = test_OpenPrinterEx(pipe, printer)

        test_ClosePrinter(pipe, handle)
        

def runtests(binding, domain, username, password):
    
    print 'Testing SPOOLSS pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_SPOOLSS_UUID, dcerpc.DCERPC_SPOOLSS_VERSION,
            domain, username, password)

    test_EnumPrinters(pipe)
