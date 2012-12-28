#!/usr/bin/env python

# script to test the dnsserver RPC protocol

import sys
from optparse import OptionParser

sys.path.insert(0, "bin/python")

import samba
import samba.getopt as options
from samba.dcerpc import dnsserver, security, dnsp


########### main code ###########
if __name__ == "__main__":
    parser = OptionParser("dnsserver [options] server")
    sambaopts = options.SambaOptions(parser)
    credopts = options.CredentialsOptionsDouble(parser)
    parser.add_option_group(credopts)

    (opts, args) = parser.parse_args()

    if len(args) < 3:
        print("Usage: dnsserver.py [options] DNSSERVER DNSZONE NEWNAME")
        sys.exit(1)

    server = args[0]
    dnszone   = args[1]
    newname   = args[2]

    lp = sambaopts.get_loadparm()
    creds = credopts.get_credentials(lp)

    if not creds.authentication_requested():
        parser.error("You must supply credentials")

    binding_str = "ncacn_ip_tcp:%s[print,sign]" % server

    dns_conn = dnsserver.dnsserver(binding_str, lp, creds)

    print("querying a NS record")
    res = dns_conn.DnssrvEnumRecords2(0x00070000,
                                      0,
                                      server,
                                      dnszone,
                                      newname,
                                      None,
                                      dnsp.DNS_TYPE_NS,
                                      0x0f,
                                      None,
                                      None)

    print("adding a NS glue record")
    name = dnsserver.DNS_RPC_NAME()
    name.str = newname

    addrec = dnsserver.DNS_RPC_RECORD()
    addrec.wType = dnsp.DNS_TYPE_NS
    addrec.dwFlags = 0
    addrec.dwSerial = 0
    addrec.dwTtlSeconds = 3600
    addrec.dwTimeStamp = 0
    addrec.dwReserved = 0
    addrec.data = name

    addrecbuf     = dnsserver.DNS_RPC_RECORD_BUF()
    addrecbuf.rec = addrec

    res = dns_conn.DnssrvUpdateRecord2(0x00070000,
                                       0,
                                       server,
                                       dnszone,
                                       newname,
                                       addrecbuf,
                                       None)


    print("querying the NS record")
    res = dns_conn.DnssrvEnumRecords2(0x00070000,
                                      0,
                                      server,
                                      dnszone,
                                      newname,
                                      None,
                                      dnsp.DNS_TYPE_NS,
                                      0x0f,
                                      None,
                                      None)
