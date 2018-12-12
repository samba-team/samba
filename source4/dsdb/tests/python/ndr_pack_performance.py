#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import optparse
import sys
sys.path.insert(0, 'bin/python')

import os
import samba
import samba.getopt as options
import random
import tempfile
import shutil
import time
import gzip

from samba.netcmd.main import cmd_sambatool

# We try to use the test infrastructure of Samba 4.3+, but if it
# doesn't work, we are probably in a back-ported patch and trying to
# run on 4.1 or something.
#
# Don't copy this horror into ordinary tests -- it is special for
# performance tests that want to apply to old versions.
try:
    from samba.tests.subunitrun import SubunitOptions, TestProgram
    ANCIENT_SAMBA = False
except ImportError:
    ANCIENT_SAMBA = True
    samba.ensure_external_module("testtools", "testtools")
    samba.ensure_external_module("subunit", "subunit/python")
    from subunit.run import SubunitTestRunner
    import unittest

from samba.samdb import SamDB
from samba.auth import system_session

from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security
from samba.dcerpc import drsuapi

parser = optparse.OptionParser("ndr_pack_performance.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

if not ANCIENT_SAMBA:
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

random.seed(1)


BIG_SD_SDDL = ''.join(
    """O:S-1-5-21-3328325300-3937145445-4190589019-512G:S-1-5-2
1-3328325300-3937145445-4190589019-512D:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-
1-5-21-3328325300-3937145445-4190589019-512)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;
SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(O
A;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e
8-ff8a58d456d2;;S-1-5-32-560)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e05
29;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a
768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f2020
10-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CI
IOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa0030
49e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc
-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf96
7aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c
04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2
-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP
;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU
)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-0
0aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0d
e6-11d0-a285-00aa003049e2;ED)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608
;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854
e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RPLCLORC;;4
828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RPLCLORC;;bf967a9c-0de6-11d0-
a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e
2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(A;CIID;RPWPCRC
CDCLCLORCWOWDSDDTSW;;;S-1-5-21-3328325300-3937145445-4190589019-519)(A;CIID;L
C;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)(OA;CIIOID;RP;4c164200-20c0-11d0-a
768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c1642
00-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CI
IOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e
5f28;RU)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0
-a285-00aa003049e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828
cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c
04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2
-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP
;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU
)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-a
d6f015e5f28;RU)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0d
e6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f6
08;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854
e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIOID;RP;b7c69e6d
-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO
ID;RPLCLORC;;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIID;RPLCLORC;;bf967
a9c-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RPLCLORC;;bf967aba-0de6-11d0-a2
85-00aa003049e2;RU)(OA;CIID;RPWPCR;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(
A;CIID;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-3328325300-3937145445-4190589019
-519)(A;CIID;LC;;;RU)(A;CIID;RPWPCRCCLCLORCWOWDSDSW;;;BA)S:AI(OU;CIIOIDSA;WP;
f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)
(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-
00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5
-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f
80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)""".split())

LITTLE_SD_SDDL = ''.join(
    """O:S-1-5-21-3328325300-3937145445-4190589019-512G:S-1-5-2
1-3328325300-3937145445-4190589019-512D:AI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;S-
1-5-21-3328325300-3937145445-4190589019-512)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;
SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(O
A;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e
8-ff8a58d456d2;;S-1-5-32-560)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e05
29;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;4c164200-20c0-11d0-a
768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;5f2020
10-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CI
IOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa0030
49e2;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc
-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf96
7aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c
04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU)(OA;CIIOID;RP;59ba2f42-79a2
-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIOID;RP
;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;RU
)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-0
0aa003049e2;RU)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0d
e6-11d0-a285-00aa003049e2;ED)""".split())

# set SCALE = 100 for normal test, or 1 for testing the test.
SCALE = 100


class UserTests(samba.tests.TestCase):

    def get_file_blob(self, filename):
        if filename.endswith('.gz'):
            f = gzip.open(filename)
        else:
            f = open(filename)
        return f.read()

    def get_desc(self, sddl):
        dummy_sid = security.dom_sid("S-2-0-0")
        return security.descriptor.from_sddl(sddl, dummy_sid)

    def get_blob(self, sddl):
        return ndr_pack(self.get_desc(sddl))

    def test_00_00_do_nothing(self):
        # this gives us an idea of the overhead
        pass

    def _test_pack(self, unpacked, cycles=10000):
        for i in range(SCALE * cycles):
            ndr_pack(unpacked)

    def _test_unpack(self, blob, cycles=10000, cls=security.descriptor):
        for i in range(SCALE * cycles):
            ndr_unpack(cls, blob)

    def _test_pack_unpack(self, desc, cycles=5000, cls=security.descriptor):
        blob2 = ndr_pack(desc)

        for i in range(SCALE * cycles):
            blob = ndr_pack(desc)
            desc = ndr_unpack(cls, blob)

        self.assertEqual(blob, blob2)

    def test_pack_big_sd(self):
        unpacked = self.get_desc(BIG_SD_SDDL)
        self._test_pack(unpacked)

    def test_unpack_big_sd(self):
        blob = self.get_blob(BIG_SD_SDDL)
        self._test_unpack(blob)

    def test_pack_unpack_big_sd(self):
        unpacked = self.get_desc(BIG_SD_SDDL)
        self._test_pack_unpack(unpacked)

    def test_pack_little_sd(self):
        unpacked = self.get_desc(LITTLE_SD_SDDL)
        self._test_pack(unpacked)

    def test_unpack_little_sd(self):
        blob = self.get_blob(LITTLE_SD_SDDL)
        self._test_unpack(blob)

    def test_pack_unpack_little_sd(self):
        unpacked = self.get_desc(LITTLE_SD_SDDL)
        self._test_pack_unpack(unpacked)

    def test_unpack_repl_sample(self):
        blob = self.get_file_blob('testdata/replication-ndrpack-example.gz')
        self._test_unpack(blob, cycles=20, cls=drsuapi.DsGetNCChangesCtr6)

    def test_pack_repl_sample(self):
        blob = self.get_file_blob('testdata/replication-ndrpack-example.gz')
        desc = ndr_unpack(drsuapi.DsGetNCChangesCtr6, blob)
        self._test_pack(desc, cycles=20)


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


if ANCIENT_SAMBA:
    runner = SubunitTestRunner()
    if not runner.run(unittest.makeSuite(UserTests)).wasSuccessful():
        sys.exit(1)
    sys.exit(0)
else:
    TestProgram(module=__name__, opts=subunitopts)
