# Unit and integration tests for traffic.py
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

# from pprint import pprint
from samba.compat import StringIO

import samba.tests

from samba.emulate import traffic


TEST_FILE = 'testdata/traffic-sample-very-short.txt'


class TrafficEmulatorTests(samba.tests.TestCase):
    def setUp(self):
        self.model = traffic.TrafficModel()

    def tearDown(self):
        del self.model

    def test_parse_ngrams_dns_included(self):
        model = traffic.TrafficModel()
        f = open(TEST_FILE)
        (conversations,
         interval,
         duration,
         dns_counts) = traffic.ingest_summaries([f], dns_mode='include')
        f.close()
        model.learn(conversations)
        expected_ngrams = {
            ('-', '-'): ['dns:0', 'dns:0', 'dns:0', 'ldap:3'],
            ('-', 'dns:0'): ['dns:0', 'dns:0', 'dns:0'],
            ('-', 'ldap:3'): ['wait:0'],
            ('cldap:3', 'cldap:3'): ['cldap:3', 'wait:0'],
            ('cldap:3', 'wait:0'): ['rpc_netlogon:29'],
            ('dns:0', 'dns:0'): ['dns:0', 'dns:0', 'dns:0', 'wait:0'],
            ('dns:0', 'wait:0'): ['cldap:3'],
            ('kerberos:', 'ldap:3'): ['-'],
            ('ldap:3', 'wait:0'): ['ldap:2'],
            ('rpc_netlogon:29', 'kerberos:'): ['ldap:3'],
            ('wait:0', 'cldap:3'): ['cldap:3'],
            ('wait:0', 'rpc_netlogon:29'): ['kerberos:']
        }
        expected_query_details = {
            'cldap:3': [('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', '')],
            'dns:0': [(), (), (), (), (), (), (), (), ()],
            'kerberos:': [('',)],
            'ldap:2': [('', '', '', '', '', '', '')],
            'ldap:3': [('',
                        '',
                        '',
                        'subschemaSubentry,dsServiceName,namingContexts,'
                        'defaultNamingContext,schemaNamingContext,'
                        'configurationNamingContext,rootDomainNamingContext,'
                        'supportedControl,supportedLDAPVersion,'
                        'supportedLDAPPolicies,supportedSASLMechanisms,'
                        'dnsHostName,ldapServiceName,serverName,'
                        'supportedCapabilities',
                        '',
                        '',
                        ''),
                       ('2', 'DC,DC', '', 'cn', '', '', '')],
            'rpc_netlogon:29': [()]
        }
        self.maxDiff = 5000
        ngrams = {k: sorted(v) for k, v in model.ngrams.items()}
        details = {k: sorted(v) for k, v in model.query_details.items()}

        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)
        # We use a stringIO instead of a temporary file
        f = StringIO()
        model.save(f)

        model2 = traffic.TrafficModel()
        f.seek(0)
        model2.load(f)

        ngrams = {k: sorted(v) for k, v in model2.ngrams.items()}
        details = {k: sorted(v) for k, v in model2.query_details.items()}
        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)

    def test_parse_ngrams(self):
        f = open(TEST_FILE)
        (conversations,
         interval,
         duration,
         dns_counts) = traffic.ingest_summaries([f])
        f.close()
        self.model.learn(conversations, dns_counts)
        # print 'ngrams'
        # pprint(self.model.ngrams, width=50)
        # print 'query_details'
        # pprint(self.model.query_details, width=55)
        expected_ngrams = {
            ('-', '-'): ['cldap:3', 'ldap:3'],
            ('-', 'cldap:3'): ['cldap:3'],
            ('-', 'ldap:3'): ['wait:0'],
            ('cldap:3', 'cldap:3'): ['cldap:3', 'wait:0'],
            ('cldap:3', 'wait:0'): ['rpc_netlogon:29'],
            ('kerberos:', 'ldap:3'): ['-'],
            ('ldap:3', 'wait:0'): ['ldap:2'],
            ('rpc_netlogon:29', 'kerberos:'): ['ldap:3'],
            ('wait:0', 'rpc_netlogon:29'): ['kerberos:']
        }

        expected_query_details = {
            'cldap:3': [('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', ''),
                        ('', '', '', 'Netlogon', '', '', '')],
            'kerberos:': [('',)],
            'ldap:2': [('', '', '', '', '', '', '')],
            'ldap:3': [('',
                        '',
                        '',
                        'subschemaSubentry,dsServiceName,namingContexts,'
                        'defaultNamingContext,schemaNamingContext,'
                        'configurationNamingContext,rootDomainNamingContext,'
                        'supportedControl,supportedLDAPVersion,'
                        'supportedLDAPPolicies,supportedSASLMechanisms,'
                        'dnsHostName,ldapServiceName,serverName,'
                        'supportedCapabilities',
                        '',
                        '',
                        ''),
                       ('2', 'DC,DC', '', 'cn', '', '', '')],
            'rpc_netlogon:29': [()]
        }
        self.maxDiff = 5000
        ngrams = {k: sorted(v) for k, v in self.model.ngrams.items()}
        details = {k: sorted(v) for k, v in self.model.query_details.items()}

        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)
        # We use a stringIO instead of a temporary file
        f = StringIO()
        self.model.save(f)

        model2 = traffic.TrafficModel()
        f.seek(0)
        model2.load(f)

        ngrams = {k: sorted(v) for k, v in model2.ngrams.items()}
        details = {k: sorted(v) for k, v in model2.query_details.items()}
        self.assertEqual(expected_ngrams, ngrams)
        self.assertEqual(expected_query_details, details)
