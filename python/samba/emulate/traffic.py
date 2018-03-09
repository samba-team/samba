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
from __future__ import print_function

import time
import os
import random
import json
import math
import sys
import signal
import itertools

from collections import OrderedDict, Counter, defaultdict
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
from samba.dsdb import UF_WORKSTATION_TRUST_ACCOUNT, UF_PASSWD_NOTREQD
from samba.dsdb import UF_NORMAL_ACCOUNT
from samba.dcerpc.misc import SEC_CHAN_WKSTA
from samba import gensec

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


def random_colour_print():
    """Return a function that prints a randomly coloured line to stderr"""
    n = 18 + random.randrange(214)
    prefix = "\033[38;5;%dm" % n

    def p(*args):
        for a in args:
            print("%s%s\033[00m" % (prefix, a), file=sys.stderr)

    return p


class FakePacketError(Exception):
    pass


class Packet(object):
    """Details of a network packet"""
    def __init__(self, fields):
        if isinstance(fields, str):
            fields = fields.rstrip('\n').split('\t')

        (timestamp,
         ip_protocol,
         stream_number,
         src,
         dest,
         protocol,
         opcode,
         desc) = fields[:8]
        extra = fields[8:]

        self.timestamp = float(timestamp)
        self.ip_protocol = ip_protocol
        try:
            self.stream_number = int(stream_number)
        except (ValueError, TypeError):
            self.stream_number = None
        self.src = int(src)
        self.dest = int(dest)
        self.protocol = protocol
        self.opcode = opcode
        self.desc = desc
        self.extra = extra

        if self.src < self.dest:
            self.endpoints = (self.src, self.dest)
        else:
            self.endpoints = (self.dest, self.src)

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
        return self.__class__([self.timestamp,
                               self.ip_protocol,
                               self.stream_number,
                               self.src,
                               self.dest,
                               self.protocol,
                               self.opcode,
                               self.desc] + self.extra)

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
            print("Conversation(%s) Missing handler %s" % \
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
        """Is the packet one that can be ignored?

        If so removing it will have no effect on the replay
        """
        if self.protocol in SKIPPED_PROTOCOLS:
            # Ignore any packets for the protocols we're not interested in.
            return False
        if self.protocol == "ldap" and self.opcode == '':
            # skip ldap continuation packets
            return False

        fn_name = 'packet_%s_%s' % (self.protocol, self.opcode)
        try:
            fn = getattr(traffic_packets, fn_name)
            if fn is traffic_packets.null_packet:
                return False
        except AttributeError:
            print("missing packet %s" % fn_name, file=sys.stderr)
            return False
        return True


class ReplayContext(object):
    """State/Context for an individual conversation between an simulated client
       and a server.
    """

    def __init__(self,
                 server=None,
                 lp=None,
                 creds=None,
                 badpassword_frequency=None,
                 prefer_kerberos=None,
                 tempdir=None,
                 statsdir=None,
                 ou=None,
                 base_dn=None,
                 domain=None,
                 domain_sid=None):

        self.server                   = server
        self.ldap_connections         = []
        self.dcerpc_connections       = []
        self.lsarpc_connections       = []
        self.lsarpc_connections_named = []
        self.drsuapi_connections      = []
        self.srvsvc_connections       = []
        self.samr_contexts            = []
        self.netlogon_connection      = None
        self.creds                    = creds
        self.lp                       = lp
        self.prefer_kerberos          = prefer_kerberos
        self.ou                       = ou
        self.base_dn                  = base_dn
        self.domain                   = domain
        self.statsdir                 = statsdir
        self.global_tempdir           = tempdir
        self.domain_sid               = domain_sid
        self.realm                    = lp.get('realm')

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
        self.generate_ldap_search_tables()
        self.next_conversation_id = itertools.count().next

    def generate_ldap_search_tables(self):
        session = system_session()

        db = SamDB(url="ldap://%s" % self.server,
                   session_info=session,
                   credentials=self.creds,
                   lp=self.lp)

        res = db.search(db.domain_dn(),
                        scope=ldb.SCOPE_SUBTREE,
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

        for k, v in dn_map.items():
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

    def generate_process_local_config(self, account, conversation):
        if account is None:
            return
        self.netbios_name             = account.netbios_name
        self.machinepass              = account.machinepass
        self.username                 = account.username
        self.userpass                 = account.userpass

        self.tempdir = mk_masked_dir(self.global_tempdir,
                                     'conversation-%d' %
                                     conversation.conversation_id)

        self.lp.set("private dir",     self.tempdir)
        self.lp.set("lock dir",        self.tempdir)
        self.lp.set("state directory", self.tempdir)
        self.lp.set("tls verify peer", "no_check")

        # If the domain was not specified, check for the environment
        # variable.
        if self.domain is None:
            self.domain = os.environ["DOMAIN"]

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
            if (self.badpassword_frequency > 0 and
               random.random() < self.badpassword_frequency):
                try:
                    f(bad)
                except:
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
        if self.prefer_kerberos:
            self.user_creds.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.user_creds.set_kerberos_state(DONT_USE_KERBEROS)

        self.user_creds_bad = Credentials()
        self.user_creds_bad.guess(self.lp)
        self.user_creds_bad.set_workstation(self.netbios_name)
        self.user_creds_bad.set_password(self.userpass[:-4])
        self.user_creds_bad.set_username(self.username)
        if self.prefer_kerberos:
            self.user_creds_bad.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.user_creds_bad.set_kerberos_state(DONT_USE_KERBEROS)

        # Credentials for ldap simple bind.
        self.simple_bind_creds = Credentials()
        self.simple_bind_creds.guess(self.lp)
        self.simple_bind_creds.set_workstation(self.netbios_name)
        self.simple_bind_creds.set_password(self.userpass)
        self.simple_bind_creds.set_username(self.username)
        self.simple_bind_creds.set_gensec_features(
            self.simple_bind_creds.get_gensec_features() | gensec.FEATURE_SEAL)
        if self.prefer_kerberos:
            self.simple_bind_creds.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.simple_bind_creds.set_kerberos_state(DONT_USE_KERBEROS)
        self.simple_bind_creds.set_bind_dn(self.user_dn)

        self.simple_bind_creds_bad = Credentials()
        self.simple_bind_creds_bad.guess(self.lp)
        self.simple_bind_creds_bad.set_workstation(self.netbios_name)
        self.simple_bind_creds_bad.set_password(self.userpass[:-4])
        self.simple_bind_creds_bad.set_username(self.username)
        self.simple_bind_creds_bad.set_gensec_features(
            self.simple_bind_creds_bad.get_gensec_features() |
            gensec.FEATURE_SEAL)
        if self.prefer_kerberos:
            self.simple_bind_creds_bad.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.simple_bind_creds_bad.set_kerberos_state(DONT_USE_KERBEROS)
        self.simple_bind_creds_bad.set_bind_dn(self.user_dn)

    def generate_machine_creds(self):
        """Generate the conversation specific machine Credentials.

        Each Conversation has an associated machine account.

        Generates machine credentials with good and bad passwords.
        """

        self.machine_creds = Credentials()
        self.machine_creds.guess(self.lp)
        self.machine_creds.set_workstation(self.netbios_name)
        self.machine_creds.set_secure_channel_type(SEC_CHAN_WKSTA)
        self.machine_creds.set_password(self.machinepass)
        self.machine_creds.set_username(self.netbios_name + "$")
        if self.prefer_kerberos:
            self.machine_creds.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.machine_creds.set_kerberos_state(DONT_USE_KERBEROS)

        self.machine_creds_bad = Credentials()
        self.machine_creds_bad.guess(self.lp)
        self.machine_creds_bad.set_workstation(self.netbios_name)
        self.machine_creds_bad.set_secure_channel_type(SEC_CHAN_WKSTA)
        self.machine_creds_bad.set_password(self.machinepass[:-4])
        self.machine_creds_bad.set_username(self.netbios_name + "$")
        if self.prefer_kerberos:
            self.machine_creds_bad.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            self.machine_creds_bad.set_kerberos_state(DONT_USE_KERBEROS)

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
            self.samr_contexts.append(SamrContext(self.server))
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
        current.cred.data = [ord(x) for x in auth["credential"]]
        current.timestamp = auth["timestamp"]

        subsequent = netr_Authenticator()
        return (current, subsequent)


class SamrContext(object):
    """State/Context associated with a samr connection.
    """
    def __init__(self, server):
        self.connection    = None
        self.handle        = None
        self.domain_handle = None
        self.domain_sid    = None
        self.group_handle  = None
        self.user_handle   = None
        self.rids          = None
        self.server        = server

    def get_connection(self):
        if not self.connection:
            self.connection = samr.samr("ncacn_ip_tcp:%s" % (self.server))
        return self.connection

    def get_handle(self):
        if not self.handle:
            c = self.get_connection()
            self.handle = c.Connect2(None, security.SEC_FLAG_MAXIMUM_ALLOWED)
        return self.handle


class Conversation(object):
    """Details of a converation between a simulated client and a server."""
    conversation_id = None

    def __init__(self, start_time=None, endpoints=None):
        self.start_time = start_time
        self.endpoints = endpoints
        self.packets = []
        self.msg = random_colour_print()
        self.client_balance = 0.0

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

    def add_short_packet(self, timestamp, p, extra, client=True):
        """Create a packet from a timestamp, and 'protocol:opcode' pair, and a
        (possibly empty) list of extra data. If client is True, assume
        this packet is from the client to the server.
        """
        protocol, opcode = p.split(':', 1)
        src, dest = self.guess_client_server()
        if not client:
            src, dest = dest, src

        desc = OP_DESCRIPTIONS.get((protocol, opcode), '')
        ip_protocol = IP_PROTOCOLS.get(protocol, '06')
        fields = [timestamp - self.start_time, ip_protocol,
                  '', src, dest,
                  protocol, opcode, desc]
        fields.extend(extra)
        packet = Packet(fields)
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
        lines = []
        for p in self.packets:
            lines.append(p.as_summary(self.start_time))
        return lines

    def replay_in_fork_with_delay(self, start, context=None, account=None):
        """Fork a new process and replay the conversation.
        """
        def signal_handler(signal, frame):
            """Signal handler closes standard out and error.

            Triggered by a sigterm, ensures that the log messages are flushed
            to disk and not lost.
            """
            sys.stderr.close()
            sys.stdout.close()
            os._exit(0)

        t = self.start_time
        now = time.time() - start
        gap = t - now
        # we are replaying strictly in order, so it is safe to sleep
        # in the main process if the gap is big enough. This reduces
        # the number of concurrent threads, which allows us to make
        # larger loads.
        if gap > 0.15 and False:
            print("sleeping for %f in main process" % (gap - 0.1),
                  file=sys.stderr)
            time.sleep(gap - 0.1)
            now = time.time() - start
            gap = t - now
            print("gap is now %f" % gap, file=sys.stderr)

        self.conversation_id = context.next_conversation_id()
        pid = os.fork()
        if pid != 0:
            return pid
        pid = os.getpid()
        signal.signal(signal.SIGTERM, signal_handler)
        # we must never return, or we'll end up running parts of the
        # parent's clean-up code. So we work in a try...finally, and
        # try to print any exceptions.

        try:
            context.generate_process_local_config(account, self)
            sys.stdin.close()
            os.close(0)
            filename = os.path.join(context.statsdir, 'stats-conversation-%d' %
                                    self.conversation_id)
            sys.stdout.close()
            sys.stdout = open(filename, 'w')

            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            miss = t - (time.time() - start)
            self.msg("starting %s [miss %.3f pid %d]" % (self, miss, pid))
            self.replay(context)
        except Exception:
            print(("EXCEPTION in child PID %d, conversation %s" % (pid, self)),
                  file=sys.stderr)
            traceback.print_exc(sys.stderr)
        finally:
            sys.stderr.close()
            sys.stdout.close()
            os._exit(0)

    def replay(self, context=None):
        start = time.time()

        for p in self.packets:
            now = time.time() - start
            gap = p.timestamp - now
            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            miss = p.timestamp - (time.time() - start)
            if context is None:
                self.msg("packet %s [miss %.3f pid %d]" % (p, miss,
                                                           os.getpid()))
                continue
            p.play(self, context)

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

        new_packets = []
        for p in self.packets:
            if p.timestamp < s or p.timestamp > e:
                continue
            new_packets.append(p)

        self.packets = new_packets
        if new_packets:
            self.start_time = new_packets[0].timestamp
        else:
            self.start_time = None

    def renormalise_times(self, start_time):
        """Adjust the packet start times relative to the new start time."""
        for p in self.packets:
            p.timestamp -= start_time

        if self.start_time is not None:
            self.start_time -= start_time


class DnsHammer(Conversation):
    """A lightweight conversation that generates a lot of dns:0 packets on
    the fly"""

    def __init__(self, dns_rate, duration):
        n = int(dns_rate * duration)
        self.times = [random.uniform(0, duration) for i in range(n)]
        self.times.sort()
        self.rate = dns_rate
        self.duration = duration
        self.start_time = 0
        self.msg = random_colour_print()

    def __str__(self):
        return ("<DnsHammer %d packets over %.1fs (rate %.2f)>" %
                (len(self.times), self.duration, self.rate))

    def replay_in_fork_with_delay(self, start, context=None, account=None):
        return Conversation.replay_in_fork_with_delay(self,
                                                      start,
                                                      context,
                                                      account)

    def replay(self, context=None):
        start = time.time()
        fn = traffic_packets.packet_dns_0
        for t in self.times:
            now = time.time() - start
            gap = t - now
            sleep_time = gap - SLEEP_OVERHEAD
            if sleep_time > 0:
                time.sleep(sleep_time)

            if context is None:
                miss = t - (time.time() - start)
                self.msg("packet %s [miss %.3f pid %d]" % (t, miss,
                                                           os.getpid()))
                continue

            packet_start = time.time()
            try:
                fn(self, self, context)
                end = time.time()
                duration = end - packet_start
                print("%f\tDNS\tdns\t0\t%f\tTrue\t" % (end, duration))
            except Exception as e:
                end = time.time()
                duration = end - packet_start
                print("%f\tDNS\tdns\t0\t%f\tFalse\t%s" % (end, duration, e))


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
            p = Packet(line)
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
    for p in packets:
        p.timestamp -= start_time
        c = conversations.get(p.endpoints)
        if c is None:
            c = Conversation()
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
    for k, v in x.iteritems():
        k2 = '\t'.join(k)
        y[k2] = v
    return y


def unstringify_keys(x):
    y = {}
    for k, v in x.iteritems():
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
        self.conversation_rate = [0, 1]

    def learn(self, conversations, dns_opcounts={}):
        prev = 0.0
        cum_duration = 0.0
        key = (NON_PACKET,) * (self.n - 1)

        server = guess_server_address(conversations)

        for k, v in dns_opcounts.items():
            self.dns_opcounts[k] += v

        if len(conversations) > 1:
            elapsed =\
                conversations[-1].start_time - conversations[0].start_time
            self.conversation_rate[0] = len(conversations)
            self.conversation_rate[1] = elapsed

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
        for k, v in self.ngrams.iteritems():
            k = '\t'.join(k)
            ngrams[k] = dict(Counter(v))

        query_details = {}
        for k, v in self.query_details.iteritems():
            query_details[k] = dict(Counter('\t'.join(x) if x else '-'
                                            for x in v))

        d = {
            'ngrams': ngrams,
            'query_details': query_details,
            'cumulative_duration': self.cumulative_duration,
            'conversation_rate': self.conversation_rate,
        }
        d['dns'] = self.dns_opcounts

        if isinstance(f, str):
            f = open(f, 'w')

        json.dump(d, f, indent=2)

    def load(self, f):
        if isinstance(f, str):
            f = open(f)

        d = json.load(f)

        for k, v in d['ngrams'].iteritems():
            k = tuple(str(k).split('\t'))
            values = self.ngrams.setdefault(k, [])
            for p, count in v.iteritems():
                values.extend([str(p)] * count)

        for k, v in d['query_details'].iteritems():
            values = self.query_details.setdefault(str(k), [])
            for p, count in v.iteritems():
                if p == '-':
                    values.extend([()] * count)
                else:
                    values.extend([tuple(str(p).split('\t'))] * count)

        if 'dns' in d:
            for k, v in d['dns'].items():
                self.dns_opcounts[k] += v

        self.cumulative_duration = d['cumulative_duration']
        self.conversation_rate = d['conversation_rate']

    def construct_conversation(self, timestamp=0.0, client=2, server=1,
                               hard_stop=None, packet_rate=1):
        """Construct a individual converation from the model."""

        c = Conversation(timestamp, (server, client))

        key = (NON_PACKET,) * (self.n - 1)

        while key in self.ngrams:
            p = random.choice(self.ngrams.get(key, NON_PACKET))
            if p == NON_PACKET:
                break
            if p in self.query_details:
                extra = random.choice(self.query_details[p])
            else:
                extra = []

            protocol, opcode = p.split(':', 1)
            if protocol == 'wait':
                log_wait_time = int(opcode) + random.random()
                wait = math.exp(log_wait_time) / (WAIT_SCALE * packet_rate)
                timestamp += wait
            else:
                log_wait = random.uniform(*NO_WAIT_LOG_TIME_RANGE)
                wait = math.exp(log_wait) / packet_rate
                timestamp += wait
                if hard_stop is not None and timestamp > hard_stop:
                    break
                c.add_short_packet(timestamp, p, extra)

            key = key[1:] + (p,)

        return c

    def generate_conversations(self, rate, duration, packet_rate=1):
        """Generate a list of conversations from the model."""

        # We run the simulation for at least ten times as long as our
        # desired duration, and take a section near the start.
        rate_n, rate_t  = self.conversation_rate

        duration2 = max(rate_t, duration * 2)
        n = rate * duration2 * rate_n / rate_t

        server = 1
        client = 2

        conversations = []
        end = duration2
        start = end - duration

        while client < n + 2:
            start = random.uniform(0, duration2)
            c = self.construct_conversation(start,
                                            client,
                                            server,
                                            hard_stop=(duration2 * 5),
                                            packet_rate=packet_rate)

            c.forget_packets_outside_window(start, end)
            c.renormalise_times(start)
            if len(c) != 0:
                conversations.append(c)
            client += 1

        print(("we have %d conversations at rate %f" %
                              (len(conversations), rate)), file=sys.stderr)
        conversations.sort()
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


def replay(conversations,
           host=None,
           creds=None,
           lp=None,
           accounts=None,
           dns_rate=0,
           duration=None,
           **kwargs):

    context = ReplayContext(server=host,
                            creds=creds,
                            lp=lp,
                            **kwargs)

    if len(accounts) < len(conversations):
        print(("we have %d accounts but %d conversations" %
               (accounts, conversations)), file=sys.stderr)

    cstack = zip(sorted(conversations,
                        key=lambda x: x.start_time, reverse=True),
                 accounts)

    # Set the process group so that the calling scripts are not killed
    # when the forked child processes are killed.
    os.setpgrp()

    start = time.time()

    if duration is None:
        # end 1 second after the last packet of the last conversation
        # to start. Conversations other than the last could still be
        # going, but we don't care.
        duration = cstack[0][0].packets[-1].timestamp + 1.0
        print("We will stop after %.1f seconds" % duration,
              file=sys.stderr)

    end = start + duration

    print("Replaying traffic for %u conversations over %d seconds"
          % (len(conversations), duration))

    children = {}
    if dns_rate:
        dns_hammer = DnsHammer(dns_rate, duration)
        cstack.append((dns_hammer, None))

    try:
        while True:
            # we spawn a batch, wait for finishers, then spawn another
            now = time.time()
            batch_end = min(now + 2.0, end)
            fork_time = 0.0
            fork_n = 0
            while cstack:
                c, account = cstack.pop()
                if c.start_time + start > batch_end:
                    cstack.append((c, account))
                    break

                st = time.time()
                pid = c.replay_in_fork_with_delay(start, context, account)
                children[pid] = c
                t = time.time()
                elapsed = t - st
                fork_time += elapsed
                fork_n += 1
                print("forked %s in pid %s (in %fs)" % (c, pid,
                                                        elapsed),
                      file=sys.stderr)

            if fork_n:
                print(("forked %d times in %f seconds (avg %f)" %
                       (fork_n, fork_time, fork_time / fork_n)),
                      file=sys.stderr)
            elif cstack:
                debug(2, "no forks in batch ending %f" % batch_end)

            while time.time() < batch_end - 1.0:
                time.sleep(0.01)
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except OSError as e:
                    if e.errno != 10:  # no child processes
                        raise
                    break
                if pid:
                    c = children.pop(pid, None)
                    print(("process %d finished conversation %s;"
                           " %d to go" %
                           (pid, c, len(children))), file=sys.stderr)

            if time.time() >= end:
                print("time to stop", file=sys.stderr)
                break

    except Exception:
        print("EXCEPTION in parent", file=sys.stderr)
        traceback.print_exc()
    finally:
        for s in (15, 15, 9):
            print(("killing %d children with -%d" %
                                 (len(children), s)), file=sys.stderr)
            for pid in children:
                try:
                    os.kill(pid, s)
                except OSError as e:
                    if e.errno != 3:  # don't fail if it has already died
                        raise
            time.sleep(0.5)
            end = time.time() + 1
            while children:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except OSError as e:
                    if e.errno != 10:
                        raise
                if pid != 0:
                    c = children.pop(pid, None)
                    print(("kill -%d %d KILLED conversation %s; "
                           "%d to go" %
                           (s, pid, c, len(children))),
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
        ldb.add({"dn":          ou.split(',', 1)[1],
                 "objectclass": "organizationalunit"})
    except LdbError as e:
        (status, _) = e
        # ignore already exists
        if status != 68:
            raise
    try:
        ldb.add({"dn":          ou,
                 "objectclass": "organizationalunit"})
    except LdbError as e:
        (status, _) = e
        # ignore already exists
        if status != 68:
            raise
    return ou


class ConversationAccounts(object):
    """Details of the machine and user accounts associated with a conversation.
    """
    def __init__(self, netbios_name, machinepass, username, userpass):
        self.netbios_name = netbios_name
        self.machinepass  = machinepass
        self.username     = username
        self.userpass     = userpass


def generate_replay_accounts(ldb, instance_id, number, password):
    """Generate a series of unique machine and user account names."""

    generate_traffic_accounts(ldb, instance_id, number, password)
    accounts = []
    for i in range(1, number + 1):
        netbios_name = "STGM-%d-%d" % (instance_id, i)
        username     = "STGU-%d-%d" % (instance_id, i)

        account = ConversationAccounts(netbios_name, password, username,
                                       password)
        accounts.append(account)
    return accounts


def generate_traffic_accounts(ldb, instance_id, number, password):
    """Create the specified number of user and machine accounts.

    As accounts are not explicitly deleted between runs. This function starts
    with the last account and iterates backwards stopping either when it
    finds an already existing account or it has generated all the required
    accounts.
    """
    print(("Generating machine and conversation accounts, "
           "as required for %d conversations" % number),
          file=sys.stderr)
    added = 0
    for i in range(number, 0, -1):
        try:
            netbios_name = "STGM-%d-%d" % (instance_id, i)
            create_machine_account(ldb, instance_id, netbios_name, password)
            added += 1
        except LdbError as e:
            (status, _) = e
            if status == 68:
                break
            else:
                raise
    if added > 0:
        print("Added %d new machine accounts" % added,
              file=sys.stderr)

    added = 0
    for i in range(number, 0, -1):
        try:
            username = "STGU-%d-%d" % (instance_id, i)
            create_user_account(ldb, instance_id, username, password)
            added += 1
        except LdbError as e:
            (status, _) = e
            if status == 68:
                break
            else:
                raise

    if added > 0:
        print("Added %d new user accounts" % added,
              file=sys.stderr)


def create_machine_account(ldb, instance_id, netbios_name, machinepass):
    """Create a machine account via ldap."""

    ou = ou_name(ldb, instance_id)
    dn = "cn=%s,%s" % (netbios_name, ou)
    utf16pw = unicode(
        '"' + machinepass.encode('utf-8') + '"', 'utf-8'
    ).encode('utf-16-le')
    start = time.time()
    ldb.add({
        "dn": dn,
        "objectclass": "computer",
        "sAMAccountName": "%s$" % netbios_name,
        "userAccountControl":
        str(UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD),
        "unicodePwd": utf16pw})
    end = time.time()
    duration = end - start
    print("%f\t0\tcreate\tmachine\t%f\tTrue\t" % (end, duration))


def create_user_account(ldb, instance_id, username, userpass):
    """Create a user account via ldap."""
    ou = ou_name(ldb, instance_id)
    user_dn = "cn=%s,%s" % (username, ou)
    utf16pw = unicode(
        '"' + userpass.encode('utf-8') + '"', 'utf-8'
    ).encode('utf-16-le')
    start = time.time()
    ldb.add({
        "dn": user_dn,
        "objectclass": "user",
        "sAMAccountName": username,
        "userAccountControl": str(UF_NORMAL_ACCOUNT),
        "unicodePwd": utf16pw
    })
    end = time.time()
    duration = end - start
    print("%f\t0\tcreate\tuser\t%f\tTrue\t" % (end, duration))


def create_group(ldb, instance_id, name):
    """Create a group via ldap."""

    ou = ou_name(ldb, instance_id)
    dn = "cn=%s,%s" % (name, ou)
    start = time.time()
    ldb.add({
        "dn": dn,
        "objectclass": "group",
    })
    end = time.time()
    duration = end - start
    print("%f\t0\tcreate\tgroup\t%f\tTrue\t" % (end, duration))


def user_name(instance_id, i):
    """Generate a user name based in the instance id"""
    return "STGU-%d-%d" % (instance_id, i)


def generate_users(ldb, instance_id, number, password):
    """Add users to the server"""
    users = 0
    for i in range(number, 0, -1):
        try:
            username = user_name(instance_id, i)
            create_user_account(ldb, instance_id, username, password)
            users += 1
        except LdbError as e:
            (status, _) = e
            # Stop if entry exists
            if status == 68:
                break
            else:
                raise

    return users


def group_name(instance_id, i):
    """Generate a group name from instance id."""
    return "STGG-%d-%d" % (instance_id, i)


def generate_groups(ldb, instance_id, number):
    """Create the required number of groups on the server."""
    groups = 0
    for i in range(number, 0, -1):
        try:
            name = group_name(instance_id, i)
            create_group(ldb, instance_id, name)
            groups += 1
        except LdbError as e:
            (status, _) = e
            # Stop if entry exists
            if status == 68:
                break
            else:
                raise
    return groups


def clean_up_accounts(ldb, instance_id):
    """Remove the created accounts and groups from the server."""
    ou = ou_name(ldb, instance_id)
    try:
        ldb.delete(ou, ["tree_delete:1"])
    except LdbError as e:
        (status, _) = e
        # ignore does not exist
        if status != 32:
            raise


def generate_users_and_groups(ldb, instance_id, password,
                              number_of_users, number_of_groups,
                              group_memberships):
    """Generate the required users and groups, allocating the users to
       those groups."""
    assignments = []
    groups_added  = 0

    create_ou(ldb, instance_id)

    print("Generating dummy user accounts", file=sys.stderr)
    users_added = generate_users(ldb, instance_id, number_of_users, password)

    if number_of_groups > 0:
        print("Generating dummy groups", file=sys.stderr)
        groups_added = generate_groups(ldb, instance_id, number_of_groups)

    if group_memberships > 0:
        print("Assigning users to groups", file=sys.stderr)
        assignments = assign_groups(number_of_groups,
                                    groups_added,
                                    number_of_users,
                                    users_added,
                                    group_memberships)
        print("Adding users to groups", file=sys.stderr)
        add_users_to_groups(ldb, instance_id, assignments)

    if (groups_added > 0 and users_added == 0 and
       number_of_groups != groups_added):
        print("Warning: the added groups will contain no members",
              file=sys.stderr)

    print(("Added %d users, %d groups and %d group memberships" %
           (users_added, groups_added, len(assignments))),
          file=sys.stderr)


def assign_groups(number_of_groups,
                  groups_added,
                  number_of_users,
                  users_added,
                  group_memberships):
    """Allocate users to groups.

    The intention is to have a few users that belong to most groups, while
    the majority of users belong to a few groups.

    A few groups will contain most users, with the remaining only having a
    few users.
    """

    def generate_user_distribution(n):
        """Probability distribution of a user belonging to a group.
        """
        dist = []
        for x in range(1, n + 1):
            p = 1 / (x + 0.001)
            dist.append(p)
        return dist

    def generate_group_distribution(n):
        """Probability distribution of a group containing a user."""
        dist = []
        for x in range(1, n + 1):
            p = 1 / (x**1.3)
            dist.append(p)
        return dist

    assignments = set()
    if group_memberships <= 0:
        return assignments

    group_dist = generate_group_distribution(number_of_groups)
    user_dist  = generate_user_distribution(number_of_users)

    # Calculate the number of group menberships required
    group_memberships = math.ceil(
        float(group_memberships) *
        (float(users_added) / float(number_of_users)))

    existing_users  = number_of_users  - users_added  - 1
    existing_groups = number_of_groups - groups_added - 1
    while len(assignments) < group_memberships:
        user        = random.randint(0, number_of_users - 1)
        group       = random.randint(0, number_of_groups - 1)
        probability = group_dist[group] * user_dist[user]

        if ((random.random() < probability * 10000) and
           (group > existing_groups or user > existing_users)):
            # the + 1 converts the array index to the corresponding
            # group or user number
            assignments.add(((user + 1), (group + 1)))

    return assignments


def add_users_to_groups(db, instance_id, assignments):
    """Add users to their assigned groups.

    Takes the list of (group,user) tuples generated by assign_groups and
    assign the users to their specified groups."""

    ou = ou_name(db, instance_id)

    def build_dn(name):
        return("cn=%s,%s" % (name, ou))

    for (user, group) in assignments:
        user_dn  = build_dn(user_name(instance_id, user))
        group_dn = build_dn(group_name(instance_id, group))

        m = ldb.Message()
        m.dn = ldb.Dn(db, group_dn)
        m["member"] = ldb.MessageElement(user_dn, ldb.FLAG_MOD_ADD, "member")
        start = time.time()
        db.modify(m)
        end = time.time()
        duration = end - start
        print("%f\t0\tadd\tuser\t%f\tTrue\t" % (end, duration))


def generate_stats(statsdir, timing_file):
    """Generate and print the summary stats for a run."""
    first      = sys.float_info.max
    last       = 0
    successful = 0
    failed     = 0
    latencies  = {}
    failures   = {}
    unique_converations = set()
    conversations = 0

    if timing_file is not None:
        tw = timing_file.write
    else:
        def tw(x):
            pass

    tw("time\tconv\tprotocol\ttype\tduration\tsuccessful\terror\n")

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
                    first        = min(float(fields[0]) - latency, first)
                    last         = max(float(fields[0]), last)

                    if protocol not in latencies:
                        latencies[protocol] = {}
                    if packet_type not in latencies[protocol]:
                        latencies[protocol][packet_type] = []

                    latencies[protocol][packet_type].append(latency)

                    if protocol not in failures:
                        failures[protocol] = {}
                    if packet_type not in failures[protocol]:
                        failures[protocol][packet_type] = 0

                    if fields[5] == 'True':
                        successful += 1
                    else:
                        failed += 1
                        failures[protocol][packet_type] += 1

                    if conversation not in unique_converations:
                        unique_converations.add(conversation)
                        conversations += 1

                    tw(line)
                except (ValueError, IndexError):
                    # not a valid line print and ignore
                    print(line, file=sys.stderr)
                    pass
    duration = last - first
    if successful == 0:
        success_rate = 0
    else:
        success_rate = successful / duration
    if failed == 0:
        failure_rate = 0
    else:
        failure_rate = failed / duration

    # print the stats in more human-readable format when stdout is going to the
    # console (as opposed to being redirected to a file)
    if sys.stdout.isatty():
        print("Total conversations:   %10d" % conversations)
        print("Successful operations: %10d (%.3f per second)"
              % (successful, success_rate))
        print("Failed operations:     %10d (%.3f per second)"
              % (failed, failure_rate))
    else:
        print("(%d, %d, %d, %.3f, %.3f)" %
              (conversations, successful, failed, success_rate, failure_rate))

    if sys.stdout.isatty():
        print("Protocol    Op Code  Description                               "
              " Count       Failed         Mean       Median          "
              "95%        Range          Max")
    else:
        print("proto\top_code\tdesc\tcount\tfailed\tmean\tmedian\t95%\trange"
              "\tmax")
    protocols = sorted(latencies.keys())
    for protocol in protocols:
        packet_types = sorted(latencies[protocol], key=opcode_key)
        for packet_type in packet_types:
            values     = latencies[protocol][packet_type]
            values     = sorted(values)
            count      = len(values)
            failed     = failures[protocol][packet_type]
            mean       = sum(values) / count
            median     = calc_percentile(values, 0.50)
            percentile = calc_percentile(values, 0.95)
            rng        = values[-1] - values[0]
            maxv       = values[-1]
            desc       = OP_DESCRIPTIONS.get((protocol, packet_type), '')
            if sys.stdout.isatty:
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
            else:
                print("%s\t%s\t%s\t%d\t%d\t%f\t%f\t%f\t%f\t%f"
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
    except:
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
    """In a testenv we end up with 0777 diectories that look an alarming
    green colour with ls. Use umask to avoid that."""
    d = os.path.join(*path)
    mask = os.umask(0o077)
    os.mkdir(d)
    os.umask(mask)
    return d
