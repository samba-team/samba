import sys, string
import dcerpc


def ResizeBufferCall(fn, pipe, r):

    r['buffer'] = None
    r['buf_size'] = 0
    
    result = fn(pipe, r)

    if result['result'] == dcerpc.WERR_INSUFFICIENT_BUFFER:
        r['buffer'] = result['buf_size'] * '\x00'
        r['buf_size'] = result['buf_size']

    result = fn(pipe, r)

    return result


def test_OpenPrinterEx(pipe, printer):

    print 'testing spoolss_OpenPrinterEx(%s)' % printer

    r = {}
    r['printername'] = '\\\\%s\\%s' % \
                       (dcerpc.dcerpc_server_name(pipe), printer)
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


def test_GetPrinter(pipe, handle):

    r = {}
    r['handle'] = handle

    for level in [0, 1, 2, 3, 4, 5, 6, 7]:

        print 'test_GetPrinter(level = %d)' % level

        r['level'] = level
        r['buffer'] = None
        r['buf_size'] = 0

        result = ResizeBufferCall(dcerpc.spoolss_GetPrinter, pipe, r)


def test_EnumForms(pipe, handle):

    print 'testing spoolss_EnumForms'

    r = {}
    r['handle'] = handle
    r['level'] = 1
    r['buffer'] = None
    r['buf_size'] = 0

    result = ResizeBufferCall(dcerpc.spoolss_EnumForms, pipe, r)

    forms = dcerpc.unmarshall_spoolss_FormInfo_array(
        result['buffer'], r['level'], result['count'])

    for form in forms:

        r = {}
        r['handle'] = handle
        r['formname'] = form['info1']['formname']
        r['level'] = 1

        result = ResizeBufferCall(dcerpc.spoolss_GetForm, pipe, r)


def test_EnumPorts(pipe, handle):

    print 'testing spoolss_EnumPorts'

    r = {}
    r['handle'] = handle
    r['level'] = 1
    r['buffer'] = None
    r['buf_size'] = 0

    result = ResizeBufferCall(dcerpc.spoolss_EnumPorts, pipe, r)


def test_DeleteForm(pipe, handle, formname):

    r = {}
    r['handle'] = handle
    r['formname'] = formname

    dcerpc.spoolss_DeleteForm(pipe, r)


def test_GetForm(pipe, handle, formname):

    r = {}
    r['handle'] = handle
    r['formname'] = formname
    r['level'] = 1

    result = ResizeBufferCall(dcerpc.spoolss_GetForm, pipe, r)

    return result['info']['info1']
    

def test_AddForm(pipe, handle):

    print 'testing spoolss_AddForm'

    formname = '__testform__'

    r = {}
    r['handle'] = handle
    r['level'] = 1
    r['info'] = {}
    r['info']['info1'] = {}
    r['info']['info1']['formname'] = formname
    r['info']['info1']['flags'] = 0
    r['info']['info1']['width'] = 1
    r['info']['info1']['length'] = 2
    r['info']['info1']['left'] = 3
    r['info']['info1']['top'] = 4
    r['info']['info1']['right'] = 5
    r['info']['info1']['bottom'] = 6

    try:
        result = dcerpc.spoolss_AddForm(pipe, r)
    except dcerpc.WERROR, arg:
        if arg[0] == dcerpc.WERR_ALREADY_EXISTS:
            test_DeleteForm(pipe, handle, formname)
        result = dcerpc.spoolss_AddForm(pipe, r)

    f = test_GetForm(pipe, handle, formname)

    if r['info']['info1'] != f:
        print 'Form type mismatch: %s != %s' % \
              (r['info']['info1'], f)
        sys.exit(1)

    r['formname'] = formname
    r['info']['info1']['unknown'] = 1

    dcerpc.spoolss_SetForm(pipe, r)

    test_DeleteForm(pipe, handle, formname)


def test_EnumPrinters(pipe):

    print 'testing spoolss_EnumPrinters'

    printer_names = None

    r = {}
    r['flags'] = 0x02
    r['server'] = None

    for level in [0, 1, 4, 5]:

        print 'test_EnumPrinters(level = %d)' % level

        r['level'] = level
        r['buf_size'] = 0
        r['buffer'] = None

        result = ResizeBufferCall(dcerpc.spoolss_EnumPrinters,pipe, r)

        printers = dcerpc.unmarshall_spoolss_PrinterInfo_array(
            result['buffer'], r['level'], result['count'])

        if level == 1:
            printer_names = map(
                lambda x: string.split(x['info1']['name'], ',')[0], printers)

    for printer in printer_names:

        handle = test_OpenPrinterEx(pipe, printer)

        test_GetPrinter(pipe, handle)

        test_EnumForms(pipe, handle)

        test_AddForm(pipe, handle)

        test_ClosePrinter(pipe, handle)
        

def runtests(binding, domain, username, password):
    
    print 'Testing SPOOLSS pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_SPOOLSS_UUID, dcerpc.DCERPC_SPOOLSS_VERSION,
            domain, username, password)

    test_EnumPrinters(pipe)
