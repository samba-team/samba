import dcerpc

def test_EnumPrinters(pipe):

    r = {}
    r['flags'] = 0x02
    r['server'] = None
    r['level'] = 1
    r['buffer'] = None
    r['buf_size'] = 0

    result = dcerpc.spoolss_EnumPrinters(pipe, r)

    if result['result'] == dcerpc.WERR_INSUFFICIENT_BUFFER:
        r['buffer'] = result['buf_size'] * '\x00'
        r['buf_size'] = result['buf_size']

        result = dcerpc.spoolss_EnumPrinters(pipe, r)

    print dcerpc.unmarshall_spoolss_PrinterInfo1(result['buffer'])

def runtests(binding, domain, username, password):
    
    print 'Testing SPOOLSS pipe'

    pipe = dcerpc.pipe_connect(binding,
            dcerpc.DCERPC_SPOOLSS_UUID, dcerpc.DCERPC_SPOOLSS_VERSION,
            domain, username, password)

    test_EnumPrinters(pipe)
