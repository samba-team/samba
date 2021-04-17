# -*- coding: utf-8 -*-
# Unix SMB/CIFS implementation. Tests for WSP
# Copyright (C) David Mulder
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys, os
import time
import traceback

sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.samba3.wspcli import conn as wspconn
from samba.dcerpc.wsp import request as wsprequest
from samba.dcerpc.wsp_data import CPMCONNECT as CPMCONNECT
from samba.credentials import Credentials
from samba.dcerpc import misc
from samba.dcerpc import wsp_data as wspdata
from samba.dcerpc import wsp as wsp

import optparse
import samba.getopt as options
import samba.tests
from samba.tests.blackbox.wsp_test import WspTestBlackboxBase as WspTestBlackboxBase

scope_flags_vector = [0x00000001]

# something is blocking the main http server from responding
# (handling requests) when we call out from the main thread
# I know that doesn't make sense but it's what appears to be
# happening. If we call out (e.g. via python client bindings)
# in another process the http server (in WspTestBlackboxBase) works
# fine. Function below runs a function in child process and blocks
# until child completes

def forkit(f):
    pid = os.fork()
    if pid == 0:
        try:
            f()
        except Exception as e:
            print("### got exception %s" % e)
            traceback.print_exc()
            os._exit(1)
        sys.stderr.flush()
        sys.stdout.flush()
        os._exit(0)

    pid2, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        signal = os.WTERMSIG(status)
        raise AssertionError("Failed with signal %d" % signal)
    return status

def root_scope_string_vector():
    root_scope = wsp.vt_lpwstr()
    root_scope.value = "\\"
    root_scope_string_vector = [root_scope]
    return root_scope_string_vector

def root_scope_bstring_vector():
    root_scope = wsp.vt_bstr()
    root_scope.value = "\\"
    root_scope_string_vector = [root_scope]
    return root_scope_string_vector

def create_lpwstr_vec(vector):
    result = []
    for val in vector:
        listitem = wsp.vt_lpwstr()
        listitem.value = val
        result.append(listitem)
    return result

def get_apropset0():
    propertyset = wsp.cdbpropset()
    propertyset.guidpropertyset = misc.GUID(wspdata.DBPROPSET_MSIDXS_ROWSETEXT)
    propertyset.cproperties = 7
    propertyset.aprops =  [wsp.cdbprop()] * propertyset.cproperties

    propertyset.aprops[0].dbpropid = 0x00000002
    propertyset.aprops[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[0].vvalue.vtype = wspdata.VT_I4
    propertyset.aprops[0].vvalue.vvalue = 0x00000000

    propertyset.aprops[1].dbpropid = 0x00000003
    propertyset.aprops[1].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[1].vvalue.vtype = wspdata.VT_BSTR
    propertyset.aprops[1].vvalue.vvalue.value = "en-ie"

    propertyset.aprops[2].dbpropid = 0x00000004
    propertyset.aprops[2].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[2].vvalue.vtype = wspdata.VT_BSTR
    propertyset.aprops[2].vvalue.vvalue.value = ""

    propertyset.aprops[3].dbpropid = 0x00000005
    propertyset.aprops[3].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[3].vvalue.vtype = wspdata.VT_BSTR
    propertyset.aprops[3].vvalue.vvalue.value = ""

    propertyset.aprops[4].dbpropid = 0x00000006
    propertyset.aprops[4].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[4].vvalue.vtype = wspdata.VT_I4
    propertyset.aprops[4].vvalue.vvalue = 0x00000000

    propertyset.aprops[5].dbpropid = 0x00000007
    propertyset.aprops[5].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[5].vvalue.vtype = wspdata.VT_I4
    propertyset.aprops[5].vvalue.vvalue = 0x00000000

    propertyset.aprops[6].dbpropid = 0x00000008
    propertyset.aprops[6].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[6].vvalue.vtype = wspdata.VT_I4
    propertyset.aprops[6].vvalue.vvalue = 0x00000000
    return propertyset

def get_apropset1():
    propertyset = wsp.cdbpropset()
    propertyset.guidpropertyset = misc.GUID(wspdata.DBPROPSET_QUERYEXT)
    propertyset.cproperties = 0x0000000B
    propertyset.aprops =  [wsp.cdbprop()] * propertyset.cproperties

    propertyset.aprops[0].dbpropid = wspdata.DBPROP_USECONTENTINDEX
    propertyset.aprops[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[0].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[0].vvalue.vvalue = 0 # False

    propertyset.aprops[1].dbpropid = wspdata.DBPROP_DEFERNONINDEXEDTRIMMING
    propertyset.aprops[1].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[1].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[1].vvalue.vvalue = 0 # False

    propertyset.aprops[2].dbpropid = wspdata.DBPROP_USEEXTENDEDDBTYPES
    propertyset.aprops[2].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[2].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[2].vvalue.vvalue = 0 # False

    propertyset.aprops[3].dbpropid = wspdata.DBPROP_IGNORENOISEONLYCLAUSES
    propertyset.aprops[3].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[3].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[3].vvalue.vvalue = 0 # False

    propertyset.aprops[4].dbpropid = wspdata.DBPROP_GENERICOPTIONS_STRING
    propertyset.aprops[4].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[4].vvalue.vtype = wspdata.VT_BSTR
    propertyset.aprops[4].vvalue.vvalue.value = ""

    propertyset.aprops[5].dbpropid = wspdata.DBPROP_DEFERCATALOGVERIFICATION
    propertyset.aprops[5].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[5].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[5].vvalue.vvalue = 0 # False

    propertyset.aprops[6].dbpropid = wspdata.DBPROP_IGNORESBRI
    propertyset.aprops[6].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[6].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[6].vvalue.vvalue = 0 # False

    propertyset.aprops[7].dbpropid = wspdata.DBPROP_GENERATEPARSETREE
    propertyset.aprops[7].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[7].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[7].vvalue.vvalue = 0 # False

    propertyset.aprops[8].dbpropid = wspdata.DBPROP_FREETEXTANYTERM
    propertyset.aprops[8].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[8].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[8].vvalue.vvalue = 0 # False

    propertyset.aprops[9].dbpropid = wspdata.DBPROP_FREETEXTUSESTEMMING
    propertyset.aprops[9].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[9].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[9].vvalue.vvalue = 0 # False

    propertyset.aprops[10].dbpropid = 0x00000009
    propertyset.aprops[10].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[10].vvalue.vtype = wspdata.VT_BOOL
    propertyset.aprops[10].vvalue.vvalue = 0 # False

    return propertyset

def get_apropset2(server):
    propertyset = wsp.cdbpropset()
    propertyset.guidpropertyset = misc.GUID(wspdata.DBPROPSET_CIFRMWRKCORE_EXT)
    propertyset.cproperties = 1
    propertyset.aprops =  [wsp.cdbprop()] * propertyset.cproperties

    propertyset.aprops[0].dbpropid = wspdata.DBPROP_MACHINE
    propertyset.aprops[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[0].vvalue.vtype = wspdata.VT_BSTR
    propertyset.aprops[0].vvalue.vvalue.value = server

    return propertyset

def get_apropset3():
    propertyset = wsp.cdbpropset()
    propertyset.guidpropertyset = misc.GUID(wspdata.DBPROPSET_CIFRMWRKCORE_EXT)
    propertyset.cproperties = 3
    propertyset.aprops =  [wsp.cdbprop()] * propertyset.cproperties

    propertyset.aprops[0].dbpropid = wspdata.DBPROP_CI_INCLUDE_SCOPES
    propertyset.aprops[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[0].vvalue.vtype = wspdata.VT_BSTR | wspdata.VT_VECTOR
    propertyset.aprops[0].vvalue.vvalue.vvector_elements = len(root_scope_bstring_vector())
    propertyset.aprops[0].vvalue.vvalue.vvector_data = root_scope_bstring_vector()

    propertyset.aprops[1].dbpropid = wspdata.DBPROP_CI_SCOPE_FLAGS
    propertyset.aprops[1].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[1].vvalue.vtype =  wspdata.VT_VECTOR | wspdata.VT_I4
    propertyset.aprops[1].vvalue.vvalue.vvector_elements = len(scope_flags_vector)
    propertyset.aprops[1].vvalue.vvalue.vvector_data = scope_flags_vector

    propertyset.aprops[2].dbpropid = wspdata.DBPROP_CI_CATALOG_NAME
    propertyset.aprops[2].colid.ekind = wspdata.DBKIND_GUID_PROPID
    propertyset.aprops[2].vvalue.vtype = wspdata.VT_LPWSTR
    propertyset.aprops[2].vvalue.vvalue.value = "Windows\\SYSTEMINDEX"

    return propertyset

def create_connectin(clientuser, clientmachine, server):
    request = wsprequest()
    request.header.msg = CPMCONNECT
    cpmconnect = request.message
    cpmconnect.iclientversion = 0x00000109
    cpmconnect.fclientisremote = 0x1
    cpmconnect.machinename = clientmachine
    cpmconnect.username = clientuser

    # connectin_propsets
    props = samba.dcerpc.wsp.connectin_propsets()
    props.cpropsets = 2

    # connectin_propsets.propertyset1
    props.propertyset1.guidpropertyset = misc.GUID(wspdata.DBPROPSET_FSCIFRMWRK_EXT)
    props.propertyset1.cproperties = 4
    aprops = [wsp.cdbprop(), wsp.cdbprop(), wsp.cdbprop(),  wsp.cdbprop()]


    aprops[0].dbpropid = wspdata.DBPROP_CI_CATALOG_NAME
    aprops[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    aprops[0].vvalue.vtype = wspdata.VT_LPWSTR
    aprops[0].vvalue.vvalue.value = "Windows\\SYSTEMINDEX"

    aprops[1].dbpropid = wspdata.DBPROP_CI_QUERY_TYPE
    aprops[1].colid.ekind = wspdata.DBKIND_GUID_PROPID
    aprops[1].vvalue.vtype = wspdata.VT_I4
    aprops[1].vvalue.vvalue = wspdata.CINORMAL

    aprops[2].dbpropid = wspdata.DBPROP_CI_SCOPE_FLAGS
    aprops[2].colid.ekind = wspdata.DBKIND_GUID_PROPID
    aprops[2].vvalue.vtype =  wspdata.VT_VECTOR | wspdata.VT_I4
    aprops[2].vvalue.vvalue.vvector_elements = len(scope_flags_vector)
    aprops[2].vvalue.vvalue.vvector_data = scope_flags_vector

    aprops[3].dbpropid = wspdata.DBPROP_CI_INCLUDE_SCOPES
    aprops[3].colid.ekind = wspdata.DBKIND_GUID_PROPID
    aprops[3].vvalue.vtype = wspdata.VT_LPWSTR | wspdata.VT_VECTOR
    aprops[3].vvalue.vvalue.vvector_elements = len(root_scope_string_vector())
    aprops[3].vvalue.vvalue.vvector_data = root_scope_string_vector()

    props.propertyset1.aprops = aprops

    # connectin_propsets.propertyset2
    props.propertyset2.guidpropertyset = misc.GUID(wspdata.DBPROPSET_CIFRMWRKCORE_EXT)
    props.propertyset2.cproperties = 1
    aprops2 = [wsp.cdbprop()]
    aprops2[0].dbpropid = wspdata.DBPROP_MACHINE
    aprops2[0].colid.ekind = wspdata.DBKIND_GUID_PROPID
    aprops2[0].vvalue.vtype =  wspdata.VT_BSTR
    aprops2[0].vvalue.vvalue.value = server

    props.propertyset2.aprops = aprops2

    # connectin_extpropsets
    ext_props = samba.dcerpc.wsp.connectin_extpropsets()
    apropertysets = []
    apropertysets.append(get_apropset0())
    apropertysets.append(get_apropset1())
    apropertysets.append(get_apropset2(server))
    apropertysets.append(get_apropset3())

    ext_props.cextpropset = len(apropertysets)
    ext_props.apropertysets = apropertysets

    blob = props.__ndr_pack__()
    cpmconnect.cbblob1 = len(blob)
    cpmconnect.propsets = list(blob)

    blob = ext_props.__ndr_pack__()
    cpmconnect.cbblob2 = len(blob)
    cpmconnect.extpropsets = list(blob)

    return request;

parser = optparse.OptionParser("tester")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)

credopts = options.CredentialsOptions(parser)

subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

class WspMsgTests(WspTestBlackboxBase):
    def setUp(self):
        super(WspMsgTests, self).setUp()
        self.servername = os.environ["SERVER"]
    def tearDown(self):
        super(WspMsgTests, self).tearDown()
    def runBadConnect(self):
        try:
            wsp_obj = wspconn(creds, lp, "badservername")
            print("Unexpected success, should have failed to connect to non existent server")
            os._exit(1)
        except Exception:
            pass

    def testBadConnect(self):
        status = forkit(self.runBadConnect)
        self.assertEqual(status, 0)

    def runInvalidConnObj(self):
        wsp_obj = wspconn(creds, lp, self.servername)
        wsp_obj.disconnect()
        try:
            connect_req = create_connectin(creds.get_username(), "client", "localhost")
            wsp_response = wsp_obj.send(connect_req)
            print("Unexpected success, 'send' should have detected invalid conn object")
            os._exit(1)
        except Exception:
            pass

    def testInvalidConnObj(self):
        status = forkit(self.runInvalidConnObj)
        self.assertEqual(status, 0)

    def runSimpleConnectIn(self):
        wsp_obj = wspconn(creds, lp, self.servername)
        retry = 3
        wsp_response = None
        connect_req = create_connectin(creds.get_username(), "client", "localhost")
        while retry:
            try:
                wsp_response = wsp_obj.send(connect_req)
                break
            except Exception as e:
                print ("got error %s" % e)
            print ("retrying message")
            time.sleep(1)
            retry = retry - 1

    # weirdly this hangs the teardown (which calls shutdown on the
    # http server, shutdown never returns)
    # the following test does exactly the same thing but additionally
    # triggers the http server to handle a request
    def testSimpleConnectIn(self):
        model = { "files" : [
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
                        { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},],
                  "base_path" : self.base_path
                }
        self.server.model = model
        self.create_model_files()
        status = forkit(self.runSimpleConnectIn)
        self.assertEqual(status, 0)

    def createCRestriction(self, guid, propid, propval, proptype):
        prop = wsp.crestriction()
        prop.ultype = wspdata.RTPROPERTY
        prop.weight = 1000

        cprop = prop.restriction
        cprop.relop = wspdata.PREQ
        cprop.property.guidpropset = guid
        cprop.property.ulkind = wspdata.PRSPEC_PROPID
        cprop.property.name_or_id = propid
        cprop.prval.vtype = proptype
        if proptype == wspdata.VT_LPWSTR:
            cprop.prval.vvalue.value = propval
        if proptype == wspdata.VT_LPWSTR | wspdata.VT_VECTOR:
            cprop.prval.vvalue.vvector_elements = len(propval)
            cprop.prval.vvalue.vvector_data = propval

        return prop


    def createQueryRequest(self):
        request = wsprequest()
        request.header.msg = wspdata.CPMCREATEQUERY
        cpmquery = request.message
        cpmquery.ccolumnsetpresent = 1
        cpmquery.columnset.count = 1
        cpmquery.columnset.indexes = [0]
        cpmquery.crestrictionpresent = 1;
        cpmquery.restrictionarray.ispresent = 1
        restrictions = [wsp.crestriction()]
        cpmquery.restrictionarray.count = 1

        restrictions[0].ultype = wspdata.RTAND
        restrictions[0].weight = 1000

        kind_prop_restr = self.createCRestriction(misc.GUID("1e3ee840-bc2b-476c-8237-2acd1a839b22"), 0x00000003, create_lpwstr_vec(["Music"]), wspdata.VT_LPWSTR | wspdata.VT_VECTOR)
        scope_prop_restr = self.createCRestriction(misc.GUID("b725f130-47ef-101a-a5f1-02608c9eebac"), 0x00000016, "FILE://%s/wsp" % self.servername, wspdata.VT_LPWSTR)
        restrictions[0].restriction.cnode = 2
        restrictions[0].restriction.panode = [kind_prop_restr, scope_prop_restr]
        cpmquery.restrictionarray.restrictions = restrictions
        cpmquery.pidmapper.count = 1
        cpmquery.pidmapper.apropspec = [wsp.cfullpropspec()]
        cpmquery.pidmapper.apropspec[0].guidpropset = misc.GUID("6b8da074-3b5c-43bc-886f-0a2cdce00b6f")
        cpmquery.pidmapper.apropspec[0].ulkind = 1
        cpmquery.pidmapper.apropspec[0].name_or_id = 0x0000064

#        print("## query %s" % request.__ndr_print__())
        return request

    def runSimpleQuery(self):

        wsp_obj = wspconn(creds, lp, self.servername)
        retry = 3
        wsp_response = None
        connect_req = create_connectin(creds.get_username(), "client", "localhost")
        while retry:
            try:
                wsp_response = wsp_obj.send(connect_req)
                break
            except Exception as e:
                print ("got error %s" % e)
            print ("retrying message")
            time.sleep(1)
            retry = retry - 1
        query_req = self.createQueryRequest()
        wsp_response = wsp_obj.send(query_req)

    def testSimpleQuery(self):
        model = { "files" : [
            { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file1")}},
            { "file" : {"url" : "file://" + os.path.join(self.base_path, "wspdir/file2")}},],
            "base_path" : self.base_path
        }
        self.server.model = model
        self.create_model_files()
        status = forkit(self.runSimpleQuery)
        self.assertEqual(status, 0)
