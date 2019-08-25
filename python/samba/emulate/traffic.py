# -*- encoding: utf-8 -*-
# Samba traffic replay and learning
#
# Copyright (C) Catalyst IT Ltd. 2017
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
#
from __future__ import print_function, division

import time
import os
import random
import json
import math
import sys
import signal
from errno import ECHILD, ESRCH

from collections import OrderedDict, Counter, defaultdict, namedtuple
from dns.resolver import query as dns_query

from samba.emulate import traffic_packets
from samba.samdb import SamDB
import ldb
from ldb import LdbError
from samba.dcerpc import ClientConnection
from samba.dcerpc import security, drsuapi, lsa
from samba.dcerpc import netlogon
from samba.dcerpc.netlogon import netr_Authenticator
from samba.dcerpc import srvsvc
from samba.dcerpc import samr
from samba.drs_utils import drs_DsBind
import traceback
from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS
from samba.auth import system_session
from samba.dsdb import (
    UF_NORMAL_ACCOUNT,
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUSTED_FOR_DELEGATION,
    UF_WORKSTATION_TRUST_ACCOUNT
)
from samba.dcerpc.misc import SEC_CHAN_BDC
from samba import gensec
from samba import sd_utils
from samba.compat import get_string
from samba.logger import get_samba_logger
import bisect

CURRENT_MODEL_VERSION = 2   # save as this
REQUIRED_MODEL_VERSION = 2  # load accepts this or greater
SLEEP_OVERHEAD = 3e-4

# we don't use None, because it complicates [de]serialisation
NON_PACKET = '-'

CLIENT_CLUES = {
    ('dns', '0'): 1.0,      # query
    ('smb', '0x72'): 1.0,   # Negotiate protocol
    ('ldap', '0'): 1.0,     # bind
    ('ldap', '3'): 1.0,     # searchRequest
    ('ldap', '2'): 1.0,     # unbindRequest
    ('cldap', '3'): 1.0,
    ('dcerpc', '11'): 1.0,  # bind
    ('dcerpc', '14'): 1.0,  # Alter_context
    ('nbns', '0'): 1.0,     # query
}

SERVER_CLUES = {
    ('dns', '1'): 1.0,      # response
    ('ldap', '1'): 1.0,     # bind response
    ('ldap', '4'): 1.0,     # search result
    ('ldap', '5'): 1.0,     # search done
    ('cldap', '5'): 1.0,
    ('dcerpc', '12'): 1.0,  # bind_ack
    ('dcerpc', '13'): 1.0,  # bind_nak
    ('dcerpc', '15'): 1.0,  # Alter_context response
}

SKIPPED_PROTOCOLS = {"smb", "smb2", "browser", "smb_netlogon"}

WAIT_SCALE = 10.0
WAIT_THRESHOLD = (1.0 / WAIT_SCALE)
NO_WAIT_LOG_TIME_RANGE = (-10, -3)

# DEBUG_LEVEL can be changed by scripts with -d
DEBUG_LEVEL = 0

LOGGER = get_samba_logger(name=__name__)


def debug(level, msg, *args):
    """Print a formatted debug message to standard error.


    :param level: The debug level, message will be printed if it is <= the
                  currently set debug level. The debug level can be set with
                  the -d option.
    :param msg:   The message to be logged, can contain C-Style format
                  specifiers
    :param args:  The parameters required by the format specifiers
    """
    if level <= DEBUG_LEVEL:
        if not args:
            print(msg, file=sys.stderr)
        else:
            print(msg % tuple(args), file=sys.stderr)


def debug_lineno(*args):
    """ Print an unformatted log message to stderr, contaning the line number
    """
    tb = traceback.extract_stack(limit=2)
    print((" %s:" "\033[01;33m"
           "%s " "\033[00m" % (tb[0][2], tb[0][1])), end=' ',
          file=sys.stderr)
    for a in args:
        print(a, file=sys.stderr)
    print(file=sys.stderr)
    sys.stderr.flush()


def random_colour_print(seeds):
    """Return a function that prints a coloured line to stderr. The colour
    of the line depends on a sort of hash of the integer arguments."""
    if seeds:
        s = 214
        for x in seeds:
            s += 17
            s *= x
            s %= 214
        prefix = "\033[38;5;%dm" % (18 + s)

        def p(*args):
            if DEBUG_LEVEL > 0:
                for a in args:
                    print("%s%s\033[00m" % (prefix, a), file=sys.stderr)
    else:
        def p(*args):
            if DEBUG_LEVEL > 0:
                for a in args:
                    print(a, file=sys.stderr)

    return p


class FakePacketError(Exception):
    pass


class Packet(object):
    """Details of a network packet"""
    __slots__ = ('timestamp',
                 'ip_protocol',
                 'stream_number',
                 'src',
                 'dest',
                 'protocol',
                 'opcode',
                 'desc',
                 'extra',
                 'endpoints')
    def __init__(self, timestamp, ip_protocol, stream_number, src, dest,
                 protocol, opcode, desc, extra):
        self.timestamp = timestamp
        self.ip_protocol = ip_protocol
        self.stream_number = stream_number
        self.src = src
        self.dest = dest
        self.protocol = protocol
        self.opcode = opcode
        self.desc = desc
        self.extra = extra
        if self.src < self.dest:
            self.endpoints = (self.src, self.dest)
        else:
            self.endpoints = (self.dest, self.src)

    @classmethod
    def from_line(cls, line):
        fields = line.rstrip('\n').split('\t')
        (timestamp,
         ip_protocol,
         stream_number,
         src,
         dest,
         protocol,
         opcode,
         desc) = fields[:8]
        extra = fields[8:]

        timestamp = float(timestamp)
        src = int(src)
        dest = int(dest)

        return cls(timestamp, ip_protocol, stream_number, src, dest,
                   protocol, opcode, desc, extra)

    def as_summary(self, time_offset=0.0):
        """Format the packet as a traffic_summary line.
        """
        extra = '\t'.join(self.extra)
        t = self.timestamp + time_offset
        return (t, '%f\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s' %
                (t,
                 self.ip_protocol,
                 self.stream_number or '',
                 self.src,
                 self.dest,
                 self.protocol,
                 self.opcode,
                 self.desc,
                 extra))

    def __str__(self):
        return ("%.3f: %d -> %d; ip %s; strm %s; prot %s; op %s; desc %s %s" %
                (self.timestamp, self.src, self.dest, self.ip_protocol or '-',
                 self.stream_number, self.protocol, self.opcode, self.desc,
                 ('«' + ' '.join(self.extra) + '»' if self.extra else '')))

    def __repr__(self):
        return "<Packet @%s>" % self

    def copy(self):
        return self.__class__(self.timestamp,
                              self.ip_protocol,
                              self.stream_number,
                              self.src,
                              self.dest,
                              self.protocol,
                              self.opcode,
                              self.desc,
                              self.extra)

    def as_packet_type(self):
        t = '%s:%s' % (self.protocol, self.opcode)
        return t

    def client_score(self):
        """A positive number means we think it is a client; a negative number
        means we think it is a server. Zero means no idea. range: -1 to 1.
        """
        key = (self.protocol, self.opcode)
        if key in CLIENT_CLUES:
            return CLIENT_CLUES[key]
        if key in SERVER_CLUES:
            return -SERVER_CLUES[key]
        return 0.0

    def play(self, conversation, context):
        """Send the packet over the network, if required.

        Some packets are ignored, i.e. for  protocols not handled,
        server response messages, or messages that are generated by the
        protocol layer associated with other packets.
        """
        fn_name = 'packet_%s_%s' % (self.protocol, self.opcode)
        try:
            fn = getattr(traffic_packets, fn_name)

        except AttributeError as e:
            print("Conversation(%s) Missing handler %s" %
                  (conversation.conversation_id, fn_name),
                  file=sys.stderr)
            return

        # Don't display a message for kerberos packets, they're not directly
        # generated they're used to indicate kerberos should be used
        if self.protocol != "kerberos":
            debug(2, "Conversation(%s) Calling handler %s" %
                     (conversation.conversation_id, fn_name))

        start = time.time()
        try:
            if fn(self, conversation, context):
                # Only collect timing data for functions that generate
                # network traffic, or fail
                end = time.time()
                duration = end - start
                print("%f\t%s\t%s\t%s\t%f\tTrue\t" %
                      (end, conversation.conversation_id, self.protocol,
                       self.opcode, duration))
        except Exception as e:
            end = time.time()
            duration = end - start
            print("%f\t%s\t%s\t%s\t%f\tFalse\t%s" %
                  (end, conversation.conversation_id, self.protocol,
                   self.opcode, duration, e))

    def __cmp__(self, other):
        return self.timestamp - other.timestamp

    def is_really_a_packet(self, missing_packet_stats=None):
        return is_a_real_packet(self.protocol, self.opcode)


def is_a_real_packet(protocol, opcode):
    """Is the packet one that can be ignored?

    If so removing it will have no effect on the replay
    """
    if protocol in SKIPPED_PROTOCOLS:
        # Ignore any packets for the protocols we're not interested in.
        return False
    if protocol == "ldap" and opcode == '':
        # skip ldap continuation packets
        return False

    fn_name = 'packet_%s_%s' % (protocol, opcode)
    fn = getattr(traffic_packets, fn_name, None)
    if fn is None:
        LOGGER.debug("missing packet %s" % fn_name, file=sys.stderr)
        return False
    if fn is traffic_packets.null_packet:
        return False
    return True


def is_a_traffic_generating_packet(protocol, opcode):
    """Return true if a packet generates traffic in its own right. Some of
    these will generate traffic in certain contexts (e.g. ldap unbind
    after a bind) but not if the conversation consists only of these packets.
    """
    if protocol == 'wait':
        return False

    if (protocol, opcode) in (
            ('kerberos', ''),
            ('ldap', '2'),
            ('dcerpc', '15'),
            ('dcerpc', '16')):
        return False

    return is_a_real_packet(protocol, opcode)


class ReplayContext(object):
    """State/Context for a conversation between an simulated client and a
       server. Some of the context is shared amongst all conversations
       and should be generated before the fork, while other context is
       specific to a particular conversation and should be generated
       *after* the fork, in generate_process_local_config().
    """
    def __init__(self,
                 server=None,
                 lp=None,
                 creds=None,
                 total_conversations=None,
                 badpassword_frequency=None,
                 prefer_kerberos=None,
                 tempdir=None,
                 statsdir=None,
                 ou=None,
                 base_dn=None,
                 domain=os.environ.get("DOMAIN"),
                 domain_sid=None,
                 instance_id=None):
        self.server                   = server
        self.netlogon_connection      = None
        self.creds                    = creds
        self.lp                       = lp
        if prefer_kerberos:
            self.kerberos_state = MUST_USE_KERBEROS
        else:
            self.kerberos_state = DONT_USE_KERBEROS
        self.ou                       = ou
        self.base_dn                  = base_dn
        self.domain                   = domain
        self.statsdir                 = statsdir
        self.global_tempdir           = tempdir
        self.domain_sid               = domain_sid
        self.realm                    = lp.get('realm')
        self.instance_id              = instance_id

        # Bad password attempt controls
        self.badpassword_frequency    = badpassword_frequency
        self.last_lsarpc_bad          = False
        self.last_lsarpc_named_bad    = False
        self.last_simple_bind_bad     = False
        self.last_bind_bad            = False
        self.last_srvsvc_bad          = False
        self.last_drsuapi_bad         = False
        self.last_netlogon_bad        = False
        self.last_samlogon_bad        = False
        self.total_conversations      = total_conversations
        self.generate_ldap_search_tables()

    def generate_ldap_search_tables(self):
        session = system_session()

        db = SamDB(url="ldap://%s" % self.server,
                   session_info=session,
                   credentials=self.creds,
                   lp=self.lp)

        res = db.search(db.domain_dn(),
                        scope=ldb.SCOPE_SUBTREE,
                        controls=["paged_results:1:1000"],
                        attrs=['dn'])

        # find a list of dns for each pattern
        # e.g. CN,CN,CN,DC,DC
        dn_map = {}
        attribute_clue_map = {
            'invocationId': []
        }

        for r in res:
            dn = str(r.dn)
            pattern = ','.join(x.lstrip()[:2] for x in dn.split(',')).upper()
            dns = dn_map.setdefault(pattern, [])
            dns.append(dn)
            if dn.startswith('CN=NTDS Settings,'):
                attribute_clue_map['invocationId'].append(dn)

        # extend the map in case we are working with a different
        # number of DC components.
        # for k, v in self.dn_map.items():
        #     print >>sys.stderr, k, len(v)

        for k in list(dn_map.keys()):
            if k[-3:] != ',DC':
                continue
            p = k[:-3]
            while p[-3:] == ',DC':
                p = p[:-3]
            for i in range(5):
                p += ',DC'
                if p != k and p in dn_map:
                    print('dn_map collison %s %s' % (k, p),
                          file=sys.stderr)
                    continue
                dn_map[p] = dn_map[k]

        self.dn_map = dn_map
        self.attribute_clue_map = attribute_clue_map

        # pre-populate DN-based search filters (it's simplest to generate them
        # once, when the test starts). These are used by guess_search_filter()
        # to avoid full-scans
        self.search_filters = {}

        # lookup all the GPO DNs
        res = db.search(db.domain_dn(), scope=ldb.SCOPE_SUBTREE, attrs=['dn'],
                        expression='(objectclass=groupPolicyContainer)')
        gpos_by_dn = "".join("(distinguishedName={0})".format(msg['dn']) for msg in res)

        # a search for the 'gPCFileSysPath' attribute is probably a GPO search
        # (as per the MS-GPOL spec) which searches for GPOs by DN
        self.search_filters['gPCFileSysPath'] = "(|{0})".format(gpos_by_dn)

        # likewise, a search for gpLink is probably the Domain SOM search part
        # of the MS-GPOL, in which case it's looking up a few OUs by DN
        ou_str = ""
        for ou in ["Domain Controllers,", "traffic_replay,", ""]:
            ou_str += "(distinguishedName={0}{1})".format(ou, db.domain_dn())
        self.search_filters['gpLink'] = "(|{0})".format(ou_str)

        # The CEP Web Service can query the AD DC to get pKICertificateTemplate
        # objects (as per MS-WCCE)
        self.search_filters['pKIExtendedKeyUsage'] = \
            '(objectCategory=pKICertificateTemplate)'

        # assume that anything querying the usnChanged is some kind of
        # synchronization tool, e.g. AD Change Detection Connector
        res = db.search('', scope=ldb.SCOPE_BASE, attrs=['highestCommittedUSN'])
        self.search_filters['usnChanged'] = \
            '(usnChanged>={0})'.format(res[0]['highestCommittedUSN'])

    # The traffic_learner script doesn't preserve the LDAP search filter, and
    # having no filter can result in a full DB scan. This is costly for a large
    # DB, and not necessarily representative of real world traffic. As there
    # several standard LDAP queries that get used by AD tools, we can apply
    # some logic and guess what the search filter might have been originally.
    def guess_search_filter(self, attrs, dn_sig, dn):

        # there are some standard spec-based searches that query fairly unique
        # attributes. Check if the search is likely one of these
        for key in self.search_filters.keys():
            if key in attrs:
                return self.search_filters[key]

        # if it's the top-level domain, assume we're looking up a single user,
        # e.g. like powershell Get-ADUser or a similar tool
        if dn_sig == 'DC,DC':
            random_user_id = random.random() % self.total_conversations
            account_name = user_name(self.instance_id, random_user_id)
            return '(&(sAMAccountName=%s)(objectClass=user))' % account_name

        # otherwise just return everything in the sub-tree
        return '(objectClass=*)'

    def generate_process_local_config(self, account, conversation):
        self.ldap_connections         = []
        self.dcerpc_connections       = []
        self.lsarpc_connections       = []
        self.lsarpc_connections_named = []
        self.drsuapi_connections      = []
        self.srvsvc_connections       = []
        self.samr_contexts            = []
        self.netbios_name             = account.netbios_name
        self.machinepass              = account.machinepass
        self.username                 = account.username
        self.userpass                 = account.userpass

        self.tempdir = mk_masked_dir(self.global_tempdir,
                                     'conversation-%d' %
                                     conversation.conversation_id)

        self.lp.set("private dir", self.tempdir)
        self.lp.set("lock dir", self.tempdir)
        self.lp.set("state directory", self.tempdir)
        self.lp.set("tls verify peer", "no_check")

        self.remoteAddress = "/root/ncalrpc_as_system"
        self.samlogon_dn   = ("cn=%s,%s" %
                              (self.netbios_name, self.ou))
        self.user_dn       = ("cn=%s,%s" %
                              (self.username, self.ou))

        self.generate_machine_creds()
        self.generate_user_creds()

    def with_random_bad_credentials(self, f, good, bad, failed_last_time):
        """Execute the supplied logon function, randomly choosing the
           bad credentials.

           Based on the frequency in badpassword_frequency randomly perform the
           function with the supplied bad credentials.
           If run with bad credentials, the function is re-run with the good
           credentials.
           failed_last_time is used to prevent consecutive bad credential
           attempts. So the over all bad credential frequency will be lower
           than that requested, but not significantly.
        """
        if not failed_last_time:
            if (self.badpassword_frequency and
                random.random() < self.badpassword_frequency):
                try:
                    f(bad)
                except Exception:
                    # Ignore any exceptions as the operation may fail
                    # as it's being performed with bad credentials
                    pass
                failed_last_time = True
            else:
                failed_last_time = False

        result = f(good)
        return (result, failed_last_time)

    def generate_user_creds(self):
        """Generate the conversation specific user Credentials.

        Each Conversation has an associated user account used to simulate
        any non Administrative user traffic.

        Generates user credentials with good and bad passwords and ldap
        simple bind credentials with good and bad passwords.
        """
        self.user_creds = Credentials()
        self.user_creds.guess(self.lp)
        self.user_creds.set_workstation(self.netbios_name)
        self.user_creds.set_password(self.userpass)
        self.user_creds.set_username(self.username)
        self.user_creds.set_domain(self.domain)
        self.user_creds.set_kerberos_state(self.kerberos_state)

        self.user_creds_bad = Credentials()
        self.user_creds_bad.guess(self.lp)
        self.user_creds_bad.set_workstation(self.netbios_name)
        self.user_creds_bad.set_password(self.userpass[:-4])
        self.user_creds_bad.set_username(self.username)
        self.user_creds_bad.set_kerberos_state(self.kerberos_state)

        # Credentials for ldap simple bind.
        self.simple_bind_creds = Credentials()
        self.simple_bind_creds.guess(self.lp)
        self.simple_bind_creds.set_workstation(self.netbios_name)
        self.simple_bind_creds.set_password(self.userpass)
        self.simple_bind_creds.set_username(self.username)
        self.simple_bind_creds.set_gensec_features(
            self.simple_bind_creds.get_gensec_features() | gensec.FEATURE_SEAL)
        self.simple_bind_creds.set_kerberos_state(self.kerberos_state)
        self.simple_bind_creds.set_bind_dn(self.user_dn)

        self.simple_bind_creds_bad = Credentials()
        self.simple_bind_creds_bad.guess(self.lp)
        self.simple_bind_creds_bad.set_workstation(self.netbios_name)
        self.simple_bind_creds_bad.set_password(self.userpass[:-4])
        self.simple_bind_creds_bad.set_username(self.username)
        self.simple_bind_creds_bad.set_gensec_features(
            self.simple_bind_creds_bad.get_gensec_features() |
            gensec.FEATURE_SEAL)
        self.simple_bind_creds_bad.set_kerberos_state(self.kerberos_state)
        self.simple_bind_creds_bad.set_bind_dn(self.user_dn)

    def generate_machine_creds(self):
        """Generate the conversation specific machine Credentials.

        Each Conversation has an associated machine account.

        Generates machine credentials with good and bad passwords.
        """

        self.machine_creds = Credentials()
        self.machine_creds.guess(self.lp)
        self.machine_creds.set_workstation(self.netbios_name)
        self.machine_creds.set_secure_channel_type(SEC_CHAN_BDC)
        self.machine_creds.set_password(self.machinepass)
        self.machine_creds.set_username(self.netbios_name + "$")
        self.machine_creds.set_domain(self.domain)
        self.machine_creds.set_kerberos_state(self.kerberos_state)

        self.machine_creds_bad = Credentials()
        self.machine_creds_bad.guess(self.lp)
        self.machine_creds_bad.set_workstation(self.netbios_name)
        self.machine_creds_bad.set_secure_channel_type(SEC_CHAN_BDC)
        self.machine_creds_bad.set_password(self.machinepass[:-4])
        self.machine_creds_bad.set_username(self.netbios_name + "$")
        self.machine_creds_bad.set_kerberos_state(self.kerberos_state)

    def get_matching_dn(self, pattern, attributes=None):
        # If the pattern is an empty string, we assume ROOTDSE,
        # Otherwise we try adding or removing DC suffixes, then
        # shorter leading patterns until we hit one.
        # e.g if there is no CN,CN,CN,CN,DC,DC
        # we first try       CN,CN,CN,CN,DC
        # and                CN,CN,CN,CN,DC,DC,DC
        # then change to        CN,CN,CN,DC,DC
        # and as last resort we use the base_dn
        attr_clue = self.attribute_clue_map.get(attributes)
        if attr_clue:
            return random.choice(attr_clue)

        pattern = pattern.upper()
        while pattern:
            if pattern in self.dn_map:
                return random.choice(self.dn_map[pattern])
            # chop one off the front and try it all again.
            pattern = pattern[3:]

        return self.base_dn

    def get_dcerpc_connection(self, new=False):
        guid = '12345678-1234-abcd-ef00-01234567cffb'  # RPC_NETLOGON UUID
        if self.dcerpc_connections and not new:
            return self.dcerpc_connections[-1]
        c = ClientConnection("ncacn_ip_tcp:%s" % self.server,
                             (guid, 1), self.lp)
        self.dcerpc_connections.append(c)
        return c

    def get_srvsvc_connection(self, new=False):
        if self.srvsvc_connections and not new:
            return self.srvsvc_connections[-1]

        def connect(creds):
            return srvsvc.srvsvc("ncacn_np:%s" % (self.server),
                                 self.lp,
                                 creds)

        (c, self.last_srvsvc_bad) = \
            self.with_random_bad_credentials(connect,
                                             self.user_creds,
                                             self.user_creds_bad,
                                             self.last_srvsvc_bad)

        self.srvsvc_connections.append(c)
        return c

    def get_lsarpc_connection(self, new=False):
        if self.lsarpc_connections and not new:
            return self.lsarpc_connections[-1]

        def connect(creds):
            binding_options = 'schannel,seal,sign'
            return lsa.lsarpc("ncacn_ip_tcp:%s[%s]" %
                              (self.server, binding_options),
                              self.lp,
                              creds)

        (c, self.last_lsarpc_bad) = \
            self.with_random_bad_credentials(connect,
                                             self.machine_creds,
                                             self.machine_creds_bad,
                                             self.last_lsarpc_bad)

        self.lsarpc_connections.append(c)
        return c

    def get_lsarpc_named_pipe_connection(self, new=False):
        if self.lsarpc_connections_named and not new:
            return self.lsarpc_connections_named[-1]

        def connect(creds):
            return lsa.lsarpc("ncacn_np:%s" % (self.server),
                              self.lp,
                              creds)

        (c, self.last_lsarpc_named_bad) = \
            self.with_random_bad_credentials(connect,
                                             self.machine_creds,
                                             self.machine_creds_bad,
                                             self.last_lsarpc_named_bad)

        self.lsarpc_connections_named.append(c)
        return c

    def get_drsuapi_connection_pair(self, new=False, unbind=False):
        """get a (drs, drs_handle) tuple"""
        if self.drsuapi_connections and not new:
            c = self.drsuapi_connections[-1]
            return c

        def connect(creds):
            binding_options = 'seal'
            binding_string = "ncacn_ip_tcp:%s[%s]" %\
                             (self.server, binding_options)
            return drsuapi.drsuapi(binding_string, self.lp, creds)

        (drs, self.last_drsuapi_bad) = \
            self.with_random_bad_credentials(connect,
                                             self.user_creds,
                                             self.user_creds_bad,
                                             self.last_drsuapi_bad)

        (drs_handle, supported_extensions) = drs_DsBind(drs)
        c = (drs, drs_handle)
        self.drsuapi_connections.append(c)
        return c

    def get_ldap_connection(self, new=False, simple=False):
        if self.ldap_connections and not new:
            return self.ldap_connections[-1]

        def simple_bind(creds):
            """
            To run simple bind against Windows, we need to run
            following commands in PowerShell:

                Install-windowsfeature ADCS-Cert-Authority
                Install-AdcsCertificationAuthority -CAType EnterpriseRootCA
                Restart-Computer

            """
            return SamDB('ldaps://%s' % self.server,
                         credentials=creds,
                         lp=self.lp)

        def sasl_bind(creds):
            return SamDB('ldap://%s' % self.server,
                         credentials=creds,
                         lp=self.lp)
        if simple:
            (samdb, self.last_simple_bind_bad) = \
                self.with_random_bad_credentials(simple_bind,
                                                 self.simple_bind_creds,
                                                 self.simple_bind_creds_bad,
                                                 self.last_simple_bind_bad)
        else:
            (samdb, self.last_bind_bad) = \
                self.with_random_bad_credentials(sasl_bind,
                                                 self.user_creds,
                                                 self.user_creds_bad,
                                                 self.last_bind_bad)

        self.ldap_connections.append(samdb)
        return samdb

    def get_samr_context(self, new=False):
        if not self.samr_contexts or new:
            self.samr_contexts.append(
                SamrContext(self.server, lp=self.lp, creds=self.creds))
        return self.samr_contexts[-1]

    def get_netlogon_connection(self):

        if self.netlogon_connection:
            return self.netlogon_connection

        def connect(creds):
            return netlogon.netlogon("ncacn_ip_tcp:%s[schannel,seal]" %
                                     (self.server),
                                     self.lp,
                                     creds)
        (c, self.last_netlogon_bad) = \
            self.with_random_bad_credentials(connect,
                                             self.machine_creds,
                                             self.machine_creds_bad,
                                             self.last_netlogon_bad)
        self.netlogon_connection = c
        return c

    def guess_a_dns_lookup(self):
        return (self.realm, 'A')

    def get_authenticator(self):
        auth = self.machine_creds.new_client_authenticator()
        current  = netr_Authenticator()
        current.cred.data = [x if isinstance(x, int) else ord(x)
                             for x in auth["credential"]]
        current.timestamp = auth["timestamp"]

        subsequent = netr_Authenticator()
        return (current, subsequent)

    def write_stats(self, filename, **kwargs):
        """Write arbitrary key/value pairs to a file in our stats directory in
        order for them to be picked up later by another process working out
        statistics."""
        filename = os.path.join(self.statsdir, filename)
        f = open(filename, 'w')
        for k, v in kwargs.items():
            print("%s: %s" % (k, v), file=f)
        f.close()


class SamrContext(object):
    """State/Context associated with a samr connection.
    """
    def __init__(self, server, lp=None, creds=None):
        self.connection    = None
        self.handle        = None
        self.domain_handle = None
        self.domain_sid    = None
        self.group_handle  = None
        self.user_handle   = None
        self.rids          = None
        self.server        = server
        self.lp            = lp
        self.creds         = creds

    def get_connection(self):
        if not self.connection:
            self.connection = samr.samr(
                "ncacn_ip_tcp:%s[seal]" % (self.server),
                lp_ctx=self.lp,
                credentials=self.creds)

        return self.connection

    def get_handle(self):
        if not self.handle:
            c = self.get_connection()
            self.handle = c.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        return self.handle


class Conversation(object):
    """Details of a converation between a simulated client and a server."""
    def __init__(self, start_time=None, endpoints=None, seq=(),
                 conversation_id=None):
        self.start_time = start_time
        self.endpoints = endpoints
        self.packets = []
        self.msg = random_colour_print(endpoints)
        self.client_balance = 0.0
        self.conversation_id = conversation_id
        for p in seq:
            self.add_short_packet(*p)

    def __cmp__(self, other):
        if self.start_time is None:
            if other.start_time is None:
                return 0
            return -1
        if other.start_time is None:
            return 1
        return self.start_time - other.start_time

    def add_packet(self, packet):
        """Add a packet object to this conversation, making a local copy with
        a conversation-relative timestamp."""
        p = packet.copy()

        if self.start_time is None:
            self.start_time = p.timestamp

        if self.endpoints is None:
            self.endpoints = p.endpoints

        if p.endpoints != self.endpoints:
            raise FakePacketError("Conversation endpoints %s don't match"
                                  "packet endpoints %s" %
                                  (self.endpoints, p.endpoints))

        p.timestamp -= self.start_time

        if p.src == p.endpoints[0]:
            self.client_balance -= p.client_score()
        else:
            self.client_balance += p.client_score()

        if p.is_really_a_packet():
            self.packets.append(p)

    def add_short_packet(self, timestamp, protocol, opcode, extra,
                         client=True, skip_unused_packets=True):
        """Create a packet from a timestamp, and 'protocol:opcode' pair, and a
        (possibly empty) list of extra data. If client is True, assume
        this packet is from the client to the server.
        """
        if skip_unused_packets and not is_a_real_packet(protocol, opcode):
            return

        src, dest = self.guess_client_server()
        if not client:
            src, dest = dest, src
        key = (protocol, opcode)
        desc = OP_DESCRIPTIONS.get(key, '')
        ip_protocol = IP_PROTOCOLS.get(protocol, '06')
        packet = Packet(timestamp - self.start_time, ip_protocol,
                        '', src, dest,
                        protocol, opcode, desc, extra)
        # XXX we're assuming the timestamp is already adjusted for
        # this conversation?
        # XXX should we adjust client balance for guessed packets?
        if packet.src == packet.endpoints[0]:
            self.client_balance -= packet.client_score()
        else:
            self.client_balance += packet.client_score()
        if packet.is_really_a_packet():
            self.packets.append(packet)

    def __str__(self):
        return ("<Conversation %s %s starting %.3f %d packets>" %
                (self.conversation_id, self.endpoints, self.start_time,
                 len(self.packets)))

    __repr__ = __str__

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)

    def get_duration(self):
        if len(self.packets) < 2:
            return 0
        return self.packets[-1].timestamp - self.packets[0].timestamp

    def replay_as_summary_lines(self):
        return [p.as_summary(self.start_time) for p in self.packets]

    def replay_with_delay(self, start, context=None, account=None):
        """Replay the conversation at the right time.
        (We're already in a fork)."""
        # first we sleep until the first packet
        t = self.start_time
        now = time.time() - start
        gap = t - now
        sleep_time = gap - SLEEP_OVERHEAD
        if sleep_time > 0:
            time.sleep(sleep_time)

        miss = (time.time() - start) - t
        self.msg("starting %s [miss %.3f]" % (self, miss))

        max_gap = 0.0
        max_sleep_miss = 0.0
        # packet times are relative to conversation start
        p_start = time.time()
        for p in self.packets:
            now = time.time() - p_start
            gap = now - p.timestamp
            if gap > max_gap:
                max_gap = gap
            if gap < 0:
                sleep_time = -gap - SLEEP_OVERHEAD
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    t = time.time() - p_start
                    if t - p.timestamp > max_sleep_miss:
                        max_sleep_miss = t - p.timestamp

            p.play(self, context)

        return max_gap, miss, max_sleep_miss

    def guess_client_server(self, server_clue=None):
        """Have a go at deciding who is the server and who is the client.
        returns (client, server)
        """
        a, b = self.endpoints

        if self.client_balance < 0:
            return (a, b)

        # in the absense of a clue, we will fall through to assuming
        # the lowest number is the server (which is usually true).

        if self.client_balance == 0 and server_clue == b:
            return (a, b)

        return (b, a)

    def forget_packets_outside_window(self, s, e):
        """Prune any packets outside the timne window we're interested in

        :param s: start of the window
        :param e: end of the window
        """
        self.packets = [p for p in self.packets if s <= p.timestamp <= e]
        self.start_time = self.packets[0].timestamp if self.packets else None

    def renormalise_times(self, start_time):
        """Adjust the packet start times relative to the new start time."""
        for p in self.packets:
            p.timestamp -= start_time

        if self.start_time is not None:
            self.start_time -= start_time


class DnsHammer(Conversation):
    """A lightweight conversation that generates a lot of dns:0 packets on
    the fly"""

    def __init__(self, dns_rate, duration, query_file=None):
        n = int(dns_rate * duration)
        self.times = [random.uniform(0, duration) for i in range(n)]
        self.times.sort()
        self.rate = dns_rate
        self.duration = duration
        self.start_time = 0
        self.query_choices = self._get_query_choices(query_file=query_file)

    def __str__(self):
        return ("<DnsHammer %d packets over %.1fs (rate %.2f)>" %
                (len(self.times), self.duration, self.rate))

    def _get_query_choices(self, query_file=None):
        """
        Read dns query choices from a file, or return default

        rname may contain format string like `{realm}`
        realm can be fetched from context.realm
        """

        if query_file:
            with open(query_file, 'r') as f:
                text = f.read()
            choices = []
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    args = line.split(',')
                    assert len(args) == 4
                    choices.append(args)
            return choices
        else:
            return [
                (0, '{realm}', 'A', 'yes'),
                (1, '{realm}', 'NS', 'yes'),
                (2, '*.{realm}', 'A', 'no'),
                (3, '*.{realm}', 'NS', 'no'),
                (10, '_msdcs.{realm}', 'A', 'yes'),
                (11, '_msdcs.{realm}', 'NS', 'yes'),
                (20, 'nx.realm.com', 'A', 'no'),
                (21, 'nx.realm.com', 'NS', 'no'),
                (22, '*.nx.realm.com', 'A', 'no'),
                (23, '*.nx.realm.com', 'NS', 'no'),
            ]

    def replay(self, context=None):
        assert context
        assert context.realm
        start = time.time()
        for t in self.times:
            now = time.time() - start
            gap = t - now
            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            opcode, rname, rtype, exist = random.choice(self.query_choices)
            rname = rname.format(realm=context.realm)
            success = True
            packet_start = time.time()
            try:
                answers = dns_query(rname, rtype)
                if exist == 'yes' and not len(answers):
                    # expect answers but didn't get, fail
                    success = False
            except Exception:
                success = False
            finally:
                end = time.time()
                duration = end - packet_start
                print("%f\tDNS\tdns\t%s\t%f\t%s\t" % (end, opcode, duration, success))


def ingest_summaries(files, dns_mode='count'):
    """Load a summary traffic summary file and generated Converations from it.
    """

    dns_counts = defaultdict(int)
    packets = []
    for f in files:
        if isinstance(f, str):
            f = open(f)
        print("Ingesting %s" % (f.name,), file=sys.stderr)
        for line in f:
            p = Packet.from_line(line)
            if p.protocol == 'dns' and dns_mode != 'include':
                dns_counts[p.opcode] += 1
            else:
                packets.append(p)

        f.close()

    if not packets:
        return [], 0

    start_time = min(p.timestamp for p in packets)
    last_packet = max(p.timestamp for p in packets)

    print("gathering packets into conversations", file=sys.stderr)
    conversations = OrderedDict()
    for i, p in enumerate(packets):
        p.timestamp -= start_time
        c = conversations.get(p.endpoints)
        if c is None:
            c = Conversation(conversation_id=(i + 2))
            conversations[p.endpoints] = c
        c.add_packet(p)

    # We only care about conversations with actual traffic, so we
    # filter out conversations with nothing to say. We do that here,
    # rather than earlier, because those empty packets contain useful
    # hints as to which end of the conversation was the client.
    conversation_list = []
    for c in conversations.values():
        if len(c) != 0:
            conversation_list.append(c)

    # This is obviously not correct, as many conversations will appear
    # to start roughly simultaneously at the beginning of the snapshot.
    # To which we say: oh well, so be it.
    duration = float(last_packet - start_time)
    mean_interval = len(conversations) / duration

    return conversation_list, mean_interval, duration, dns_counts


def guess_server_address(conversations):
    # we guess the most common address.
    addresses = Counter()
    for c in conversations:
        addresses.update(c.endpoints)
    if addresses:
        return addresses.most_common(1)[0]


def stringify_keys(x):
    y = {}
    for k, v in x.items():
        k2 = '\t'.join(k)
        y[k2] = v
    return y


def unstringify_keys(x):
    y = {}
    for k, v in x.items():
        t = tuple(str(k).split('\t'))
        y[t] = v
    return y


class TrafficModel(object):
    def __init__(self, n=3):
        self.ngrams = {}
        self.query_details = {}
        self.n = n
        self.dns_opcounts = defaultdict(int)
        self.cumulative_duration = 0.0
        self.packet_rate = [0, 1]

    def learn(self, conversations, dns_opcounts={}):
        prev = 0.0
        cum_duration = 0.0
        key = (NON_PACKET,) * (self.n - 1)

        server = guess_server_address(conversations)

        for k, v in dns_opcounts.items():
            self.dns_opcounts[k] += v

        if len(conversations) > 1:
            first = conversations[0].start_time
            total = 0
            last = first + 0.1
            for c in conversations:
                total += len(c)
                last = max(last, c.packets[-1].timestamp)

            self.packet_rate[0] = total
            self.packet_rate[1] = last - first

        for c in conversations:
            client, server = c.guess_client_server(server)
            cum_duration += c.get_duration()
            key = (NON_PACKET,) * (self.n - 1)
            for p in c:
                if p.src != client:
                    continue

                elapsed = p.timestamp - prev
                prev = p.timestamp
                if elapsed > WAIT_THRESHOLD:
                    # add the wait as an extra state
                    wait = 'wait:%d' % (math.log(max(1.0,
                                                     elapsed * WAIT_SCALE)))
                    self.ngrams.setdefault(key, []).append(wait)
                    key = key[1:] + (wait,)

                short_p = p.as_packet_type()
                self.query_details.setdefault(short_p,
                                              []).append(tuple(p.extra))
                self.ngrams.setdefault(key, []).append(short_p)
                key = key[1:] + (short_p,)

        self.cumulative_duration += cum_duration
        # add in the end
        self.ngrams.setdefault(key, []).append(NON_PACKET)

    def save(self, f):
        ngrams = {}
        for k, v in self.ngrams.items():
            k = '\t'.join(k)
            ngrams[k] = dict(Counter(v))

        query_details = {}
        for k, v in self.query_details.items():
            query_details[k] = dict(Counter('\t'.join(x) if x else '-'
                                            for x in v))

        d = {
            'ngrams': ngrams,
            'query_details': query_details,
            'cumulative_duration': self.cumulative_duration,
            'packet_rate': self.packet_rate,
            'version': CURRENT_MODEL_VERSION
        }
        d['dns'] = self.dns_opcounts

        if isinstance(f, str):
            f = open(f, 'w')

        json.dump(d, f, indent=2)

    def load(self, f):
        if isinstance(f, str):
            f = open(f)

        d = json.load(f)

        try:
            version = d["version"]
            if version < REQUIRED_MODEL_VERSION:
                raise ValueError("the model file is version %d; "
                                 "version %d is required" %
                                 (version, REQUIRED_MODEL_VERSION))
        except KeyError:
                raise ValueError("the model file lacks a version number; "
                                 "version %d is required" %
                                 (REQUIRED_MODEL_VERSION))

        for k, v in d['ngrams'].items():
            k = tuple(str(k).split('\t'))
            values = self.ngrams.setdefault(k, [])
            for p, count in v.items():
                values.extend([str(p)] * count)
            values.sort()

        for k, v in d['query_details'].items():
            values = self.query_details.setdefault(str(k), [])
            for p, count in v.items():
                if p == '-':
                    values.extend([()] * count)
                else:
                    values.extend([tuple(str(p).split('\t'))] * count)
            values.sort()

        if 'dns' in d:
            for k, v in d['dns'].items():
                self.dns_opcounts[k] += v

        self.cumulative_duration = d['cumulative_duration']
        self.packet_rate = d['packet_rate']

    def construct_conversation_sequence(self, timestamp=0.0,
                                        hard_stop=None,
                                        replay_speed=1,
                                        ignore_before=0,
                                        persistence=0):
        """Construct an individual conversation packet sequence from the
        model.
        """
        c = []
        key = (NON_PACKET,) * (self.n - 1)
        if ignore_before is None:
            ignore_before = timestamp - 1

        while True:
            p = random.choice(self.ngrams.get(key, (NON_PACKET,)))
            if p == NON_PACKET:
                if timestamp < ignore_before:
                    break
                if random.random() > persistence:
                    print("ending after %s (persistence %.1f)" % (key, persistence),
                          file=sys.stderr)
                    break

                p = 'wait:%d' % random.randrange(5, 12)
                print("trying %s instead of end" % p, file=sys.stderr)

            if p in self.query_details:
                extra = random.choice(self.query_details[p])
            else:
                extra = []

            protocol, opcode = p.split(':', 1)
            if protocol == 'wait':
                log_wait_time = int(opcode) + random.random()
                wait = math.exp(log_wait_time) / (WAIT_SCALE * replay_speed)
                timestamp += wait
            else:
                log_wait = random.uniform(*NO_WAIT_LOG_TIME_RANGE)
                wait = math.exp(log_wait) / replay_speed
                timestamp += wait
                if hard_stop is not None and timestamp > hard_stop:
                    break
                if timestamp >= ignore_before:
                    c.append((timestamp, protocol, opcode, extra))

            key = key[1:] + (p,)
            if key[-2][:5] == 'wait:' and key[-1][:5] == 'wait:':
                # two waits in a row can only be caused by "persistence"
                # tricks, and will not result in any packets being found.
                # Instead we pretend this is a fresh start.
                key = (NON_PACKET,) * (self.n - 1)

        return c

    def scale_to_packet_rate(self, scale):
        rate_n, rate_t  = self.packet_rate
        return scale * rate_n / rate_t

    def packet_rate_to_scale(self, pps):
        rate_n, rate_t  = self.packet_rate
        return  pps * rate_t / rate_n

    def generate_conversation_sequences(self, packet_rate, duration, replay_speed=1,
                                        persistence=0):
        """Generate a list of conversation descriptions from the model."""

        # We run the simulation for ten times as long as our desired
        # duration, and take the section at the end.
        lead_in = 9 * duration
        target_packets = int(packet_rate * duration)
        conversations = []
        n_packets = 0

        while n_packets < target_packets:
            start = random.uniform(-lead_in, duration)
            c = self.construct_conversation_sequence(start,
                                                     hard_stop=duration,
                                                     replay_speed=replay_speed,
                                                     ignore_before=0,
                                                     persistence=persistence)
            # will these "packets" generate actual traffic?
            # some (e.g. ldap unbind) will not generate anything
            # if the previous packets are not there, and if the
            # conversation only has those it wastes a process doing nothing.
            for timestamp, protocol, opcode, extra in c:
                if is_a_traffic_generating_packet(protocol, opcode):
                    break
            else:
                continue

            conversations.append(c)
            n_packets += len(c)

        scale = self.packet_rate_to_scale(packet_rate)
        print(("we have %d packets (target %d) in %d conversations at %.1f/s "
               "(scale %f)" % (n_packets, target_packets, len(conversations),
                               packet_rate, scale)),
              file=sys.stderr)
        conversations.sort()  # sorts by first element == start time
        return conversations


def seq_to_conversations(seq, server=1, client=2):
    conversations = []
    for s in seq:
        if s:
            c = Conversation(s[0][0], (server, client), s)
            client += 1
            conversations.append(c)
    return conversations


IP_PROTOCOLS = {
    'dns': '11',
    'rpc_netlogon': '06',
    'kerberos': '06',      # ratio 16248:258
    'smb': '06',
    'smb2': '06',
    'ldap': '06',
    'cldap': '11',
    'lsarpc': '06',
    'samr': '06',
    'dcerpc': '06',
    'epm': '06',
    'drsuapi': '06',
    'browser': '11',
    'smb_netlogon': '11',
    'srvsvc': '06',
    'nbns': '11',
}

OP_DESCRIPTIONS = {
    ('browser', '0x01'): 'Host Announcement (0x01)',
    ('browser', '0x02'): 'Request Announcement (0x02)',
    ('browser', '0x08'): 'Browser Election Request (0x08)',
    ('browser', '0x09'): 'Get Backup List Request (0x09)',
    ('browser', '0x0c'): 'Domain/Workgroup Announcement (0x0c)',
    ('browser', '0x0f'): 'Local Master Announcement (0x0f)',
    ('cldap', '3'): 'searchRequest',
    ('cldap', '5'): 'searchResDone',
    ('dcerpc', '0'): 'Request',
    ('dcerpc', '11'): 'Bind',
    ('dcerpc', '12'): 'Bind_ack',
    ('dcerpc', '13'): 'Bind_nak',
    ('dcerpc', '14'): 'Alter_context',
    ('dcerpc', '15'): 'Alter_context_resp',
    ('dcerpc', '16'): 'AUTH3',
    ('dcerpc', '2'): 'Response',
    ('dns', '0'): 'query',
    ('dns', '1'): 'response',
    ('drsuapi', '0'): 'DsBind',
    ('drsuapi', '12'): 'DsCrackNames',
    ('drsuapi', '13'): 'DsWriteAccountSpn',
    ('drsuapi', '1'): 'DsUnbind',
    ('drsuapi', '2'): 'DsReplicaSync',
    ('drsuapi', '3'): 'DsGetNCChanges',
    ('drsuapi', '4'): 'DsReplicaUpdateRefs',
    ('epm', '3'): 'Map',
    ('kerberos', ''): '',
    ('ldap', '0'): 'bindRequest',
    ('ldap', '1'): 'bindResponse',
    ('ldap', '2'): 'unbindRequest',
    ('ldap', '3'): 'searchRequest',
    ('ldap', '4'): 'searchResEntry',
    ('ldap', '5'): 'searchResDone',
    ('ldap', ''): '*** Unknown ***',
    ('lsarpc', '14'): 'lsa_LookupNames',
    ('lsarpc', '15'): 'lsa_LookupSids',
    ('lsarpc', '39'): 'lsa_QueryTrustedDomainInfoBySid',
    ('lsarpc', '40'): 'lsa_SetTrustedDomainInfo',
    ('lsarpc', '6'): 'lsa_OpenPolicy',
    ('lsarpc', '76'): 'lsa_LookupSids3',
    ('lsarpc', '77'): 'lsa_LookupNames4',
    ('nbns', '0'): 'query',
    ('nbns', '1'): 'response',
    ('rpc_netlogon', '21'): 'NetrLogonDummyRoutine1',
    ('rpc_netlogon', '26'): 'NetrServerAuthenticate3',
    ('rpc_netlogon', '29'): 'NetrLogonGetDomainInfo',
    ('rpc_netlogon', '30'): 'NetrServerPasswordSet2',
    ('rpc_netlogon', '39'): 'NetrLogonSamLogonEx',
    ('rpc_netlogon', '40'): 'DsrEnumerateDomainTrusts',
    ('rpc_netlogon', '45'): 'NetrLogonSamLogonWithFlags',
    ('rpc_netlogon', '4'): 'NetrServerReqChallenge',
    ('samr', '0',): 'Connect',
    ('samr', '16'): 'GetAliasMembership',
    ('samr', '17'): 'LookupNames',
    ('samr', '18'): 'LookupRids',
    ('samr', '19'): 'OpenGroup',
    ('samr', '1'): 'Close',
    ('samr', '25'): 'QueryGroupMember',
    ('samr', '34'): 'OpenUser',
    ('samr', '36'): 'QueryUserInfo',
    ('samr', '39'): 'GetGroupsForUser',
    ('samr', '3'): 'QuerySecurity',
    ('samr', '5'): 'LookupDomain',
    ('samr', '64'): 'Connect5',
    ('samr', '6'): 'EnumDomains',
    ('samr', '7'): 'OpenDomain',
    ('samr', '8'): 'QueryDomainInfo',
    ('smb', '0x04'): 'Close (0x04)',
    ('smb', '0x24'): 'Locking AndX (0x24)',
    ('smb', '0x2e'): 'Read AndX (0x2e)',
    ('smb', '0x32'): 'Trans2 (0x32)',
    ('smb', '0x71'): 'Tree Disconnect (0x71)',
    ('smb', '0x72'): 'Negotiate Protocol (0x72)',
    ('smb', '0x73'): 'Session Setup AndX (0x73)',
    ('smb', '0x74'): 'Logoff AndX (0x74)',
    ('smb', '0x75'): 'Tree Connect AndX (0x75)',
    ('smb', '0xa2'): 'NT Create AndX (0xa2)',
    ('smb2', '0'): 'NegotiateProtocol',
    ('smb2', '11'): 'Ioctl',
    ('smb2', '14'): 'Find',
    ('smb2', '16'): 'GetInfo',
    ('smb2', '18'): 'Break',
    ('smb2', '1'): 'SessionSetup',
    ('smb2', '2'): 'SessionLogoff',
    ('smb2', '3'): 'TreeConnect',
    ('smb2', '4'): 'TreeDisconnect',
    ('smb2', '5'): 'Create',
    ('smb2', '6'): 'Close',
    ('smb2', '8'): 'Read',
    ('smb_netlogon', '0x12'): 'SAM LOGON request from client (0x12)',
    ('smb_netlogon', '0x17'): ('SAM Active Directory Response - '
                               'user unknown (0x17)'),
    ('srvsvc', '16'): 'NetShareGetInfo',
    ('srvsvc', '21'): 'NetSrvGetInfo',
}


def expand_short_packet(p, timestamp, src, dest, extra):
    protocol, opcode = p.split(':', 1)
    desc = OP_DESCRIPTIONS.get((protocol, opcode), '')
    ip_protocol = IP_PROTOCOLS.get(protocol, '06')

    line = [timestamp, ip_protocol, '', src, dest, protocol, opcode, desc]
    line.extend(extra)
    return '\t'.join(line)


def flushing_signal_handler(signal, frame):
    """Signal handler closes standard out and error.

    Triggered by a sigterm, ensures that the log messages are flushed
    to disk and not lost.
    """
    sys.stderr.close()
    sys.stdout.close()
    os._exit(0)


def replay_seq_in_fork(cs, start, context, account, client_id, server_id=1):
    """Fork a new process and replay the conversation sequence."""
    # We will need to reseed the random number generator or all the
    # clients will end up using the same sequence of random
    # numbers. random.randint() is mixed in so the initial seed will
    # have an effect here.
    seed = client_id * 1000 + random.randint(0, 999)

    # flush our buffers so messages won't be written by both sides
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid != 0:
        return pid

    # we must never return, or we'll end up running parts of the
    # parent's clean-up code. So we work in a try...finally, and
    # try to print any exceptions.
    try:
        random.seed(seed)
        endpoints = (server_id, client_id)
        status = 0
        t = cs[0][0]
        c = Conversation(t, endpoints, seq=cs, conversation_id=client_id)
        signal.signal(signal.SIGTERM, flushing_signal_handler)

        context.generate_process_local_config(account, c)
        sys.stdin.close()
        os.close(0)
        filename = os.path.join(context.statsdir, 'stats-conversation-%d' %
                                c.conversation_id)
        f = open(filename, 'w')
        try:
            sys.stdout.close()
            os.close(1)
        except IOError as e:
            LOGGER.info("stdout closing failed with %s" % e)
            pass

        sys.stdout = f
        now = time.time() - start
        gap = t - now
        sleep_time = gap - SLEEP_OVERHEAD
        if sleep_time > 0:
            time.sleep(sleep_time)

        max_lag, start_lag, max_sleep_miss = c.replay_with_delay(start=start,
                                                                 context=context)
        print("Maximum lag: %f" % max_lag)
        print("Start lag: %f" % start_lag)
        print("Max sleep miss: %f" % max_sleep_miss)

    except Exception:
        status = 1
        print(("EXCEPTION in child PID %d, conversation %s" % (os.getpid(), c)),
              file=sys.stderr)
        traceback.print_exc(sys.stderr)
        sys.stderr.flush()
    finally:
        sys.stderr.close()
        sys.stdout.close()
        os._exit(status)


def dnshammer_in_fork(dns_rate, duration, context, query_file=None):
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid != 0:
        return pid

    sys.stdin.close()
    os.close(0)

    try:
        sys.stdout.close()
        os.close(1)
    except IOError as e:
        LOGGER.warn("stdout closing failed with %s" % e)
        pass
    filename = os.path.join(context.statsdir, 'stats-dns')
    sys.stdout = open(filename, 'w')

    try:
        status = 0
        signal.signal(signal.SIGTERM, flushing_signal_handler)
        hammer = DnsHammer(dns_rate, duration, query_file=query_file)
        hammer.replay(context=context)
    except Exception:
        status = 1
        print(("EXCEPTION in child PID %d, the DNS hammer" % (os.getpid())),
              file=sys.stderr)
        traceback.print_exc(sys.stderr)
    finally:
        sys.stderr.close()
        sys.stdout.close()
        os._exit(status)


def replay(conversation_seq,
           host=None,
           creds=None,
           lp=None,
           accounts=None,
           dns_rate=0,
           dns_query_file=None,
           duration=None,
           latency_timeout=1.0,
           stop_on_any_error=False,
           **kwargs):

    context = ReplayContext(server=host,
                            creds=creds,
                            lp=lp,
                            total_conversations=len(conversation_seq),
                            **kwargs)

    if len(accounts) < len(conversation_seq):
        raise ValueError(("we have %d accounts but %d conversations" %
                          (len(accounts), len(conversation_seq))))

    # Set the process group so that the calling scripts are not killed
    # when the forked child processes are killed.
    os.setpgrp()

    # we delay the start by a bit to allow all the forks to get up and
    # running.
    delay = len(conversation_seq) * 0.02
    start = time.time() + delay

    if duration is None:
        # end slightly after the last packet of the last conversation
        # to start. Conversations other than the last could still be
        # going, but we don't care.
        duration = conversation_seq[-1][-1][0] + latency_timeout

    print("We will start in %.1f seconds" % delay,
          file=sys.stderr)
    print("We will stop after %.1f seconds" % (duration + delay),
          file=sys.stderr)
    print("runtime %.1f seconds" % duration,
          file=sys.stderr)

    # give one second grace for packets to finish before killing begins
    end = start + duration + 1.0

    LOGGER.info("Replaying traffic for %u conversations over %d seconds"
          % (len(conversation_seq), duration))

    context.write_stats('intentions',
                        Planned_conversations=len(conversation_seq),
                        Planned_packets=sum(len(x) for x in conversation_seq))

    children = {}
    try:
        if dns_rate:
            pid = dnshammer_in_fork(dns_rate, duration, context,
                                    query_file=dns_query_file)
            children[pid] = 1

        for i, cs in enumerate(conversation_seq):
            account = accounts[i]
            client_id = i + 2
            pid = replay_seq_in_fork(cs, start, context, account, client_id)
            children[pid] = client_id

        # HERE, we are past all the forks
        t = time.time()
        print("all forks done in %.1f seconds, waiting %.1f" %
              (t - start + delay, t - start),
              file=sys.stderr)

        while time.time() < end and children:
            time.sleep(0.003)
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except OSError as e:
                if e.errno != ECHILD:  # no child processes
                    raise
                break
            if pid:
                c = children.pop(pid, None)
                if DEBUG_LEVEL > 0:
                    print(("process %d finished conversation %d;"
                           " %d to go" %
                           (pid, c, len(children))), file=sys.stderr)
                if stop_on_any_error and status != 0:
                    break

    except Exception:
        print("EXCEPTION in parent", file=sys.stderr)
        traceback.print_exc()
    finally:
        context.write_stats('unfinished',
                            Unfinished_conversations=len(children))

        for s in (15, 15, 9):
            print(("killing %d children with -%d" %
                   (len(children), s)), file=sys.stderr)
            for pid in children:
                try:
                    os.kill(pid, s)
                except OSError as e:
                    if e.errno != ESRCH:  # don't fail if it has already died
                        raise
            time.sleep(0.5)
            end = time.time() + 1
            while children:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except OSError as e:
                    if e.errno != ECHILD:
                        raise
                if pid != 0:
                    c = children.pop(pid, None)
                    if c is None:
                        print("children is %s, no pid found" % children)
                        sys.stderr.flush()
                        sys.stdout.flush()
                        os._exit(1)
                    print(("kill -%d %d KILLED conversation; "
                           "%d to go" %
                           (s, pid, len(children))),
                          file=sys.stderr)
                if time.time() >= end:
                    break

            if not children:
                break
            time.sleep(1)

        if children:
            print("%d children are missing" % len(children),
                  file=sys.stderr)

        # there may be stragglers that were forked just as ^C was hit
        # and don't appear in the list of children. We can get them
        # with killpg, but that will also kill us, so this is^H^H would be
        # goodbye, except we cheat and pretend to use ^C (SIG_INTERRUPT),
        # so as not to have to fuss around writing signal handlers.
        try:
            os.killpg(0, 2)
        except KeyboardInterrupt:
            print("ignoring fake ^C", file=sys.stderr)


def openLdb(host, creds, lp):
    session = system_session()
    ldb = SamDB(url="ldap://%s" % host,
                session_info=session,
                options=['modules:paged_searches'],
                credentials=creds,
                lp=lp)
    return ldb


def ou_name(ldb, instance_id):
    """Generate an ou name from the instance id"""
    return "ou=instance-%d,ou=traffic_replay,%s" % (instance_id,
                                                    ldb.domain_dn())


def create_ou(ldb, instance_id):
    """Create an ou, all created user and machine accounts will belong to it.

    This allows all the created resources to be cleaned up easily.
    """
    ou = ou_name(ldb, instance_id)
    try:
        ldb.add({"dn": ou.split(',', 1)[1],
                 "objectclass": "organizationalunit"})
    except LdbError as e:
        (status, _) = e.args
        # ignore already exists
        if status != 68:
            raise
    try:
        ldb.add({"dn": ou,
                 "objectclass": "organizationalunit"})
    except LdbError as e:
        (status, _) = e.args
        # ignore already exists
        if status != 68:
            raise
    return ou


# ConversationAccounts holds details of the machine and user accounts
# associated with a conversation.
#
# We use a named tuple to reduce shared memory usage.
ConversationAccounts = namedtuple('ConversationAccounts',
                                  ('netbios_name',
                                   'machinepass',
                                   'username',
                                   'userpass'))


def generate_replay_accounts(ldb, instance_id, number, password):
    """Generate a series of unique machine and user account names."""

    accounts = []
    for i in range(1, number + 1):
        netbios_name = machine_name(instance_id, i)
        username = user_name(instance_id, i)

        account = ConversationAccounts(netbios_name, password, username,
                                       password)
        accounts.append(account)
    return accounts


def create_machine_account(ldb, instance_id, netbios_name, machinepass,
                           traffic_account=True):
    """Create a machine account via ldap."""

    ou = ou_name(ldb, instance_id)
    dn = "cn=%s,%s" % (netbios_name, ou)
    utf16pw = ('"%s"' % get_string(machinepass)).encode('utf-16-le')

    if traffic_account:
        # we set these bits for the machine account otherwise the replayed
        # traffic throws up NT_STATUS_NO_TRUST_SAM_ACCOUNT errors
        account_controls = str(UF_TRUSTED_FOR_DELEGATION |
                               UF_SERVER_TRUST_ACCOUNT)

    else:
        account_controls = str(UF_WORKSTATION_TRUST_ACCOUNT)

    ldb.add({
        "dn": dn,
        "objectclass": "computer",
        "sAMAccountName": "%s$" % netbios_name,
        "userAccountControl": account_controls,
        "unicodePwd": utf16pw})


def create_user_account(ldb, instance_id, username, userpass):
    """Create a user account via ldap."""
    ou = ou_name(ldb, instance_id)
    user_dn = "cn=%s,%s" % (username, ou)
    utf16pw = ('"%s"' % get_string(userpass)).encode('utf-16-le')
    ldb.add({
        "dn": user_dn,
        "objectclass": "user",
        "sAMAccountName": username,
        "userAccountControl": str(UF_NORMAL_ACCOUNT),
        "unicodePwd": utf16pw
    })

    # grant user write permission to do things like write account SPN
    sdutils = sd_utils.SDUtils(ldb)
    sdutils.dacl_add_ace(user_dn, "(A;;WP;;;PS)")


def create_group(ldb, instance_id, name):
    """Create a group via ldap."""

    ou = ou_name(ldb, instance_id)
    dn = "cn=%s,%s" % (name, ou)
    ldb.add({
        "dn": dn,
        "objectclass": "group",
        "sAMAccountName": name,
    })


def user_name(instance_id, i):
    """Generate a user name based in the instance id"""
    return "STGU-%d-%d" % (instance_id, i)


def search_objectclass(ldb, objectclass='user', attr='sAMAccountName'):
    """Seach objectclass, return attr in a set"""
    objs = ldb.search(
        expression="(objectClass={})".format(objectclass),
        attrs=[attr]
    )
    return {str(obj[attr]) for obj in objs}


def generate_users(ldb, instance_id, number, password):
    """Add users to the server"""
    existing_objects = search_objectclass(ldb, objectclass='user')
    users = 0
    for i in range(number, 0, -1):
        name = user_name(instance_id, i)
        if name not in existing_objects:
            create_user_account(ldb, instance_id, name, password)
            users += 1
            if users % 50 == 0:
                LOGGER.info("Created %u/%u users" % (users, number))

    return users


def machine_name(instance_id, i, traffic_account=True):
    """Generate a machine account name from instance id."""
    if traffic_account:
        # traffic accounts correspond to a given user, and use different
        # userAccountControl flags to ensure packets get processed correctly
        # by the DC
        return "STGM-%d-%d" % (instance_id, i)
    else:
        # Otherwise we're just generating computer accounts to simulate a
        # semi-realistic network. These use the default computer
        # userAccountControl flags, so we use a different account name so that
        # we don't try to use them when generating packets
        return "PC-%d-%d" % (instance_id, i)


def generate_machine_accounts(ldb, instance_id, number, password,
                              traffic_account=True):
    """Add machine accounts to the server"""
    existing_objects = search_objectclass(ldb, objectclass='computer')
    added = 0
    for i in range(number, 0, -1):
        name = machine_name(instance_id, i, traffic_account)
        if name + "$" not in existing_objects:
            create_machine_account(ldb, instance_id, name, password,
                                   traffic_account)
            added += 1
            if added % 50 == 0:
                LOGGER.info("Created %u/%u machine accounts" % (added, number))

    return added


def group_name(instance_id, i):
    """Generate a group name from instance id."""
    return "STGG-%d-%d" % (instance_id, i)


def generate_groups(ldb, instance_id, number):
    """Create the required number of groups on the server."""
    existing_objects = search_objectclass(ldb, objectclass='group')
    groups = 0
    for i in range(number, 0, -1):
        name = group_name(instance_id, i)
        if name not in existing_objects:
            create_group(ldb, instance_id, name)
            groups += 1
            if groups % 1000 == 0:
                LOGGER.info("Created %u/%u groups" % (groups, number))

    return groups


def clean_up_accounts(ldb, instance_id):
    """Remove the created accounts and groups from the server."""
    ou = ou_name(ldb, instance_id)
    try:
        ldb.delete(ou, ["tree_delete:1"])
    except LdbError as e:
        (status, _) = e.args
        # ignore does not exist
        if status != 32:
            raise


def generate_users_and_groups(ldb, instance_id, password,
                              number_of_users, number_of_groups,
                              group_memberships, max_members,
                              machine_accounts, traffic_accounts=True):
    """Generate the required users and groups, allocating the users to
       those groups."""
    memberships_added = 0
    groups_added = 0
    computers_added = 0

    create_ou(ldb, instance_id)

    LOGGER.info("Generating dummy user accounts")
    users_added = generate_users(ldb, instance_id, number_of_users, password)

    LOGGER.info("Generating dummy machine accounts")
    computers_added = generate_machine_accounts(ldb, instance_id,
                                                machine_accounts, password,
                                                traffic_accounts)

    if number_of_groups > 0:
        LOGGER.info("Generating dummy groups")
        groups_added = generate_groups(ldb, instance_id, number_of_groups)

    if group_memberships > 0:
        LOGGER.info("Assigning users to groups")
        assignments = GroupAssignments(number_of_groups,
                                       groups_added,
                                       number_of_users,
                                       users_added,
                                       group_memberships,
                                       max_members)
        LOGGER.info("Adding users to groups")
        add_users_to_groups(ldb, instance_id, assignments)
        memberships_added = assignments.total()

    if (groups_added > 0 and users_added == 0 and
       number_of_groups != groups_added):
        LOGGER.warning("The added groups will contain no members")

    LOGGER.info("Added %d users (%d machines), %d groups and %d memberships" %
                (users_added, computers_added, groups_added,
                 memberships_added))


class GroupAssignments(object):
    def __init__(self, number_of_groups, groups_added, number_of_users,
                 users_added, group_memberships, max_members):

        self.count = 0
        self.generate_group_distribution(number_of_groups)
        self.generate_user_distribution(number_of_users, group_memberships)
        self.max_members = max_members
        self.assignments = defaultdict(list)
        self.assign_groups(number_of_groups, groups_added, number_of_users,
                           users_added, group_memberships)

    def cumulative_distribution(self, weights):
        # make sure the probabilities conform to a cumulative distribution
        # spread between 0.0 and 1.0. Dividing by the weighted total gives each
        # probability a proportional share of 1.0. Higher probabilities get a
        # bigger share, so are more likely to be picked. We use the cumulative
        # value, so we can use random.random() as a simple index into the list
        dist = []
        total = sum(weights)
        if total == 0:
            return None

        cumulative = 0.0
        for probability in weights:
            cumulative += probability
            dist.append(cumulative / total)
        return dist

    def generate_user_distribution(self, num_users, num_memberships):
        """Probability distribution of a user belonging to a group.
        """
        # Assign a weighted probability to each user. Use the Pareto
        # Distribution so that some users are in a lot of groups, and the
        # bulk of users are in only a few groups. If we're assigning a large
        # number of group memberships, use a higher shape. This means slightly
        # fewer outlying users that are in large numbers of groups. The aim is
        # to have no users belonging to more than ~500 groups.
        if num_memberships > 5000000:
            shape = 3.0
        elif num_memberships > 2000000:
            shape = 2.5
        elif num_memberships > 300000:
            shape = 2.25
        else:
            shape = 1.75

        weights = []
        for x in range(1, num_users + 1):
            p = random.paretovariate(shape)
            weights.append(p)

        # convert the weights to a cumulative distribution between 0.0 and 1.0
        self.user_dist = self.cumulative_distribution(weights)

    def generate_group_distribution(self, n):
        """Probability distribution of a group containing a user."""

        # Assign a weighted probability to each user. Probability decreases
        # as the group-ID increases
        weights = []
        for x in range(1, n + 1):
            p = 1 / (x**1.3)
            weights.append(p)

        # convert the weights to a cumulative distribution between 0.0 and 1.0
        self.group_weights = weights
        self.group_dist = self.cumulative_distribution(weights)

    def generate_random_membership(self):
        """Returns a randomly generated user-group membership"""

        # the list items are cumulative distribution values between 0.0 and
        # 1.0, which makes random() a handy way to index the list to get a
        # weighted random user/group. (Here the user/group returned are
        # zero-based array indexes)
        user = bisect.bisect(self.user_dist, random.random())
        group = bisect.bisect(self.group_dist, random.random())

        return user, group

    def users_in_group(self, group):
        return self.assignments[group]

    def get_groups(self):
        return self.assignments.keys()

    def cap_group_membership(self, group, max_members):
        """Prevent the group's membership from exceeding the max specified"""
        num_members = len(self.assignments[group])
        if num_members >= max_members:
            LOGGER.info("Group {0} has {1} members".format(group, num_members))

            # remove this group and then recalculate the cumulative
            # distribution, so this group is no longer selected
            self.group_weights[group - 1] = 0
            new_dist = self.cumulative_distribution(self.group_weights)
            self.group_dist = new_dist

    def add_assignment(self, user, group):
        # the assignments are stored in a dictionary where key=group,
        # value=list-of-users-in-group (indexing by group-ID allows us to
        # optimize for DB membership writes)
        if user not in self.assignments[group]:
            self.assignments[group].append(user)
            self.count += 1

        # check if there'a cap on how big the groups can grow
        if self.max_members:
            self.cap_group_membership(group, self.max_members)

    def assign_groups(self, number_of_groups, groups_added,
                      number_of_users, users_added, group_memberships):
        """Allocate users to groups.

        The intention is to have a few users that belong to most groups, while
        the majority of users belong to a few groups.

        A few groups will contain most users, with the remaining only having a
        few users.
        """

        if group_memberships <= 0:
            return

        # Calculate the number of group menberships required
        group_memberships = math.ceil(
            float(group_memberships) *
            (float(users_added) / float(number_of_users)))

        if self.max_members:
            group_memberships = min(group_memberships,
                                    self.max_members * number_of_groups)

        existing_users  = number_of_users  - users_added  - 1
        existing_groups = number_of_groups - groups_added - 1
        while self.total() < group_memberships:
            user, group = self.generate_random_membership()

            if group > existing_groups or user > existing_users:
                # the + 1 converts the array index to the corresponding
                # group or user number
                self.add_assignment(user + 1, group + 1)

    def total(self):
        return self.count


def add_users_to_groups(db, instance_id, assignments):
    """Takes the assignments of users to groups and applies them to the DB."""

    total = assignments.total()
    count = 0
    added = 0

    for group in assignments.get_groups():
        users_in_group = assignments.users_in_group(group)
        if len(users_in_group) == 0:
            continue

        # Split up the users into chunks, so we write no more than 1K at a
        # time. (Minimizing the DB modifies is more efficient, but writing
        # 10K+ users to a single group becomes inefficient memory-wise)
        for chunk in range(0, len(users_in_group), 1000):
            chunk_of_users = users_in_group[chunk:chunk + 1000]
            add_group_members(db, instance_id, group, chunk_of_users)

            added += len(chunk_of_users)
            count += 1
            if count % 50 == 0:
                LOGGER.info("Added %u/%u memberships" % (added, total))

def add_group_members(db, instance_id, group, users_in_group):
    """Adds the given users to group specified."""

    ou = ou_name(db, instance_id)

    def build_dn(name):
        return("cn=%s,%s" % (name, ou))

    group_dn = build_dn(group_name(instance_id, group))
    m = ldb.Message()
    m.dn = ldb.Dn(db, group_dn)

    for user in users_in_group:
        user_dn = build_dn(user_name(instance_id, user))
        idx = "member-" + str(user)
        m[idx] = ldb.MessageElement(user_dn, ldb.FLAG_MOD_ADD, "member")

    db.modify(m)


def generate_stats(statsdir, timing_file):
    """Generate and print the summary stats for a run."""
    first      = sys.float_info.max
    last       = 0
    successful = 0
    failed     = 0
    latencies  = {}
    failures   = Counter()
    unique_conversations = set()
    if timing_file is not None:
        tw = timing_file.write
    else:
        def tw(x):
            pass

    tw("time\tconv\tprotocol\ttype\tduration\tsuccessful\terror\n")

    float_values = {
        'Maximum lag': 0,
        'Start lag': 0,
        'Max sleep miss': 0,
    }
    int_values = {
        'Planned_conversations': 0,
        'Planned_packets': 0,
        'Unfinished_conversations': 0,
    }

    for filename in os.listdir(statsdir):
        path = os.path.join(statsdir, filename)
        with open(path, 'r') as f:
            for line in f:
                try:
                    fields       = line.rstrip('\n').split('\t')
                    conversation = fields[1]
                    protocol     = fields[2]
                    packet_type  = fields[3]
                    latency      = float(fields[4])
                    t = float(fields[0])
                    first        = min(t - latency, first)
                    last         = max(t, last)

                    op = (protocol, packet_type)
                    latencies.setdefault(op, []).append(latency)
                    if fields[5] == 'True':
                        successful += 1
                    else:
                        failed += 1
                        failures[op] += 1

                    unique_conversations.add(conversation)

                    tw(line)
                except (ValueError, IndexError):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        if k in float_values:
                            float_values[k] = max(float(v),
                                                  float_values[k])
                        elif k in int_values:
                            int_values[k] = max(int(v),
                                                int_values[k])
                        else:
                            print(line, file=sys.stderr)
                    else:
                        # not a valid line print and ignore
                        print(line, file=sys.stderr)

    duration = last - first
    if successful == 0:
        success_rate = 0
    else:
        success_rate = successful / duration
    if failed == 0:
        failure_rate = 0
    else:
        failure_rate = failed / duration

    conversations = len(unique_conversations)

    print("Total conversations:   %10d" % conversations)
    print("Successful operations: %10d (%.3f per second)"
          % (successful, success_rate))
    print("Failed operations:     %10d (%.3f per second)"
          % (failed, failure_rate))

    for k, v in sorted(float_values.items()):
        print("%-28s %f" % (k.replace('_', ' ') + ':', v))
    for k, v in sorted(int_values.items()):
        print("%-28s %d" % (k.replace('_', ' ') + ':', v))

    print("Protocol    Op Code  Description                               "
          " Count       Failed         Mean       Median          "
          "95%        Range          Max")

    ops = {}
    for proto, packet in latencies:
        if proto not in ops:
            ops[proto] = set()
        ops[proto].add(packet)
    protocols = sorted(ops.keys())

    for protocol in protocols:
        packet_types = sorted(ops[protocol], key=opcode_key)
        for packet_type in packet_types:
            op = (protocol, packet_type)
            values     = latencies[op]
            values     = sorted(values)
            count      = len(values)
            failed     = failures[op]
            mean       = sum(values) / count
            median     = calc_percentile(values, 0.50)
            percentile = calc_percentile(values, 0.95)
            rng        = values[-1] - values[0]
            maxv       = values[-1]
            desc       = OP_DESCRIPTIONS.get(op, '')
            print("%-12s   %4s  %-35s %12d %12d %12.6f "
                  "%12.6f %12.6f %12.6f %12.6f"
                  % (protocol,
                     packet_type,
                     desc,
                     count,
                     failed,
                     mean,
                     median,
                     percentile,
                     rng,
                     maxv))


def opcode_key(v):
    """Sort key for the operation code to ensure that it sorts numerically"""
    try:
        return "%03d" % int(v)
    except ValueError:
        return v


def calc_percentile(values, percentile):
    """Calculate the specified percentile from the list of values.

    Assumes the list is sorted in ascending order.
    """

    if not values:
        return 0
    k = (len(values) - 1) * percentile
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values[int(k)]
    d0 = values[int(f)] * (c - k)
    d1 = values[int(c)] * (k - f)
    return d0 + d1


def mk_masked_dir(*path):
    """In a testenv we end up with 0777 directories that look an alarming
    green colour with ls. Use umask to avoid that."""
    # py3 os.mkdir can do this
    d = os.path.join(*path)
    mask = os.umask(0o077)
    os.mkdir(d)
    os.umask(mask)
    return d
