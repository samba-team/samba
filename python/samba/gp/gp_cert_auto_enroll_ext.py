# gp_cert_auto_enroll_ext samba group policy
# Copyright (C) David Mulder <dmulder@suse.com> 2021
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

import os
import operator
import requests
from samba.gp.gpclass import gp_pol_ext, gp_applier, GPOSTATE
from samba import Ldb
from samba.dcerpc import misc
from samba.ndr import ndr_unpack

from ldb import SCOPE_SUBTREE, SCOPE_BASE
from samba.auth import system_session
from samba.gp.gpclass import get_dc_hostname
import base64
from shutil import which
from subprocess import Popen, PIPE
import re
import json
from samba.gp.util.logging import log
import struct
try:
    from cryptography.hazmat.primitives.serialization.pkcs7 import \
        load_der_pkcs7_certificates
except ModuleNotFoundError:
    def load_der_pkcs7_certificates(x): return []
    log.error('python cryptography missing pkcs7 support. '
              'Certificate chain parsing will fail')
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from samba.common import get_string

cert_wrap = b"""
-----BEGIN CERTIFICATE-----
%s
-----END CERTIFICATE-----"""
endpoint_re = '(https|HTTPS)://(?P<server>[a-zA-Z0-9.-]+)/ADPolicyProvider' + \
              '_CEP_(?P<auth>[a-zA-Z]+)/service.svc/CEP'

global_trust_dirs = ['/etc/pki/trust/anchors',           # SUSE
                     '/etc/pki/ca-trust/source/anchors', # RHEL/Fedora
                     '/usr/local/share/ca-certificates'] # Debian/Ubuntu


def group_and_sort_end_point_information(end_point_information):
    """Group and Sort End Point Information.

    [MS-CAESO] 4.4.5.3.2.3
    In this step autoenrollment processes the end point information by grouping
    it by CEP ID and sorting in the order with which it will use the end point
    to access the CEP information.
    """
    # Create groups of the CertificateEnrollmentPolicyEndPoint instances that
    # have the same value of the EndPoint.PolicyID datum.
    end_point_groups = {}
    for e in end_point_information:
        if e['PolicyID'] not in end_point_groups.keys():
            end_point_groups[e['PolicyID']] = []
        end_point_groups[e['PolicyID']].append(e)

    # Sort each group by following these rules:
    for end_point_group in end_point_groups.values():
        # Sort the CertificateEnrollmentPolicyEndPoint instances in ascending
        # order based on the EndPoint.Cost value.
        end_point_group.sort(key=lambda e: e['Cost'])

        # For instances that have the same EndPoint.Cost:
        cost_list = [e['Cost'] for e in end_point_group]
        costs = set(cost_list)
        for cost in costs:
            i = cost_list.index(cost)
            j = len(cost_list)-operator.indexOf(reversed(cost_list), cost)-1
            if i == j:
                continue

            # Sort those that have EndPoint.Authentication equal to Kerberos
            # first. Then sort those that have EndPoint.Authentication equal to
            # Anonymous. The rest of the CertificateEnrollmentPolicyEndPoint
            # instances follow in an arbitrary order.
            def sort_auth(e):
                # 0x2 - Kerberos
                if e['AuthFlags'] == 0x2:
                    return 0
                # 0x1 - Anonymous
                elif e['AuthFlags'] == 0x1:
                    return 1
                else:
                    return 2
            end_point_group[i:j+1] = sorted(end_point_group[i:j+1],
                                            key=sort_auth)
    return list(end_point_groups.values())

def obtain_end_point_information(entries):
    """Obtain End Point Information.

    [MS-CAESO] 4.4.5.3.2.2
    In this step autoenrollment initializes the
    CertificateEnrollmentPolicyEndPoints table.
    """
    end_point_information = {}
    section = 'Software\\Policies\\Microsoft\\Cryptography\\PolicyServers\\'
    for e in entries:
        if not e.keyname.startswith(section):
            continue
        name = e.keyname.replace(section, '')
        if name not in end_point_information.keys():
            end_point_information[name] = {}
        end_point_information[name][e.valuename] = e.data
    for ca in end_point_information.values():
        m = re.match(endpoint_re, ca['URL'])
        if m:
            name = '%s-CA' % m.group('server').replace('.', '-')
            ca['name'] = name
            ca['hostname'] = m.group('server')
            ca['auth'] = m.group('auth')
        elif ca['URL'].lower() != 'ldap:':
            edata = { 'endpoint': ca['URL'] }
            log.error('Failed to parse the endpoint', edata)
            return {}
    end_point_information = \
        group_and_sort_end_point_information(end_point_information.values())
    return end_point_information

def fetch_certification_authorities(ldb):
    """Initialize CAs.

    [MS-CAESO] 4.4.5.3.1.2
    """
    result = []
    basedn = ldb.get_default_basedn()
    # Autoenrollment MUST do an LDAP search for the CA information
    # (pKIEnrollmentService) objects under the following container:
    dn = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,%s' % basedn
    attrs = ['cACertificate', 'cn', 'dNSHostName']
    expr = '(objectClass=pKIEnrollmentService)'
    res = ldb.search(dn, SCOPE_SUBTREE, expr, attrs)
    if len(res) == 0:
        return result
    for es in res:
        data = { 'name': get_string(es['cn'][0]),
                 'hostname': get_string(es['dNSHostName'][0]),
                 'cACertificate': get_string(base64.b64encode(es['cACertificate'][0]))
               }
        result.append(data)
    return result

def fetch_template_attrs(ldb, name, attrs=None):
    if attrs is None:
        attrs = ['msPKI-Minimal-Key-Size']
    basedn = ldb.get_default_basedn()
    dn = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,%s' % basedn
    expr = '(cn=%s)' % name
    res = ldb.search(dn, SCOPE_SUBTREE, expr, attrs)
    if len(res) == 1 and 'msPKI-Minimal-Key-Size' in res[0]:
        return dict(res[0])
    else:
        return {'msPKI-Minimal-Key-Size': ['2048']}

def format_root_cert(cert):
    return cert_wrap % re.sub(b"(.{64})", b"\\1\n", cert.encode(), 0, re.DOTALL)

def find_cepces_submit():
    certmonger_dirs = [os.environ.get("PATH"), '/usr/lib/certmonger',
                       '/usr/libexec/certmonger']
    return which('cepces-submit', path=':'.join(certmonger_dirs))

def get_supported_templates(server):
    cepces_submit = find_cepces_submit()
    if not cepces_submit:
        log.error('Failed to find cepces-submit')
        return []

    env = os.environ
    env['CERTMONGER_OPERATION'] = 'GET-SUPPORTED-TEMPLATES'
    p = Popen([cepces_submit, '--server=%s' % server, '--auth=Kerberos'],
              env=env, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    if p.returncode != 0:
        data = {'Error': err.decode()}
        log.error('Failed to fetch the list of supported templates.', data)
    return out.strip().split()


def getca(ca, url, trust_dir):
    """Fetch Certificate Chain from the CA."""
    root_cert = os.path.join(trust_dir, '%s.crt' % ca['name'])
    root_certs = []

    try:
        r = requests.get(url=url, params={'operation': 'GetCACert',
                                          'message': 'CAIdentifier'})
    except requests.exceptions.ConnectionError:
        log.warn('Could not connect to Network Device Enrollment Service.')
        r = None
    if r is None or r.content == b'' or r.headers['Content-Type'] == 'text/html':
        log.warn('Unable to fetch root certificates (requires NDES).')
        if 'cACertificate' in ca:
            log.warn('Installing the server certificate only.')
            der_certificate = base64.b64decode(ca['cACertificate'])
            try:
                cert = load_der_x509_certificate(der_certificate)
            except TypeError:
                cert = load_der_x509_certificate(der_certificate,
                                                 default_backend())
            cert_data = cert.public_bytes(Encoding.PEM)
            with open(root_cert, 'wb') as w:
                w.write(cert_data)
            root_certs.append(root_cert)
        return root_certs

    if r.headers['Content-Type'] == 'application/x-x509-ca-cert':
        # Older versions of load_der_x509_certificate require a backend param
        try:
            cert = load_der_x509_certificate(r.content)
        except TypeError:
            cert = load_der_x509_certificate(r.content, default_backend())
        cert_data = cert.public_bytes(Encoding.PEM)
        with open(root_cert, 'wb') as w:
            w.write(cert_data)
        root_certs.append(root_cert)
    elif r.headers['Content-Type'] == 'application/x-x509-ca-ra-cert':
        certs = load_der_pkcs7_certificates(r.content)
        for i in range(0, len(certs)):
            cert = certs[i].public_bytes(Encoding.PEM)
            filename, extension = root_cert.rsplit('.', 1)
            dest = '%s.%d.%s' % (filename, i, extension)
            with open(dest, 'wb') as w:
                w.write(cert)
            root_certs.append(dest)
    else:
        log.warn('getca: Wrong (or missing) MIME content type')

    return root_certs


def find_global_trust_dir():
    """Return the global trust dir using known paths from various Linux distros."""
    for trust_dir in global_trust_dirs:
        if os.path.isdir(trust_dir):
            return trust_dir
    return global_trust_dirs[0]

def update_ca_command():
    """Return the command to update the CA trust store."""
    return which('update-ca-certificates') or which('update-ca-trust')

def changed(new_data, old_data):
    """Return True if any key present in both dicts has changed."""
    return any((new_data[k] != old_data[k] if k in old_data else False)
            for k in new_data.keys())

def cert_enroll(ca, ldb, trust_dir, private_dir, auth='Kerberos'):
    """Install the root certificate chain."""
    data = dict({'files': [], 'templates': []}, **ca)
    url = 'http://%s/CertSrv/mscep/mscep.dll/pkiclient.exe?' % ca['hostname']

    log.info("Try to get root or server certificates")

    root_certs = getca(ca, url, trust_dir)
    data['files'].extend(root_certs)
    global_trust_dir = find_global_trust_dir()
    for src in root_certs:
        # Symlink the certs to global trust dir
        dst = os.path.join(global_trust_dir, os.path.basename(src))
        try:
            os.symlink(src, dst)
            data['files'].append(dst)
            log.info("Created symlink: %s -> %s" % (src, dst))
        except PermissionError:
            log.warn('Failed to symlink root certificate to the'
                     ' admin trust anchors')
        except FileNotFoundError:
            log.warn('Failed to symlink root certificate to the'
                     ' admin trust anchors.'
                     ' The directory was not found', global_trust_dir)
        except FileExistsError:
            # If we're simply downloading a renewed cert, the symlink
            # already exists. Ignore the FileExistsError. Preserve the
            # existing symlink in the unapply data.
            data['files'].append(dst)

    update = update_ca_command()
    log.info("Running %s" % (update))
    if update is not None:
        ret = Popen([update]).wait()
        if ret != 0:
            log.error('Failed to run %s' % (update))

    # Setup Certificate Auto Enrollment
    getcert = which('getcert')
    cepces_submit = find_cepces_submit()
    if getcert is not None and cepces_submit is not None:
        p = Popen([getcert, 'add-ca', '-c', ca['name'], '-e',
                  '%s --server=%s --auth=%s' % (cepces_submit,
                  ca['hostname'], auth)],
                  stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        log.debug(out.decode())
        if p.returncode != 0:
            if p.returncode == 2:
                log.info('The CA [%s] already exists' % ca['name'])
            else:
                data = {'Error': err.decode(), 'CA': ca['name']}
                log.error('Failed to add Certificate Authority', data)

        supported_templates = get_supported_templates(ca['hostname'])
        for template in supported_templates:
            attrs = fetch_template_attrs(ldb, template)
            nickname = '%s.%s' % (ca['name'], template.decode())
            keyfile = os.path.join(private_dir, '%s.key' % nickname)
            certfile = os.path.join(trust_dir, '%s.crt' % nickname)
            p = Popen([getcert, 'request', '-c', ca['name'],
                       '-T', template.decode(),
                       '-I', nickname, '-k', keyfile, '-f', certfile,
                       '-g', attrs['msPKI-Minimal-Key-Size'][0]],
                       stdout=PIPE, stderr=PIPE)
            out, err = p.communicate()
            log.debug(out.decode())
            if p.returncode != 0:
                if p.returncode == 2:
                    log.info('The template [%s] already exists' % (nickname))
                else:
                    data = {'Error': err.decode(), 'Certificate': nickname}
                    log.error('Failed to request certificate', data)

            data['files'].extend([keyfile, certfile])
            data['templates'].append(nickname)
        if update is not None:
            ret = Popen([update]).wait()
            if ret != 0:
                log.error('Failed to run %s' % (update))
    else:
        log.warn('certmonger and cepces must be installed for ' +
                 'certificate auto enrollment to work')
    return json.dumps(data)

class gp_cert_auto_enroll_ext(gp_pol_ext, gp_applier):
    def __str__(self):
        return r'Cryptography\AutoEnrollment'

    def unapply(self, guid, attribute, value):
        ca_cn = base64.b64decode(attribute)
        data = json.loads(value)
        getcert = which('getcert')
        if getcert is not None:
            Popen([getcert, 'remove-ca', '-c', ca_cn]).wait()
            for nickname in data['templates']:
                Popen([getcert, 'stop-tracking', '-i', nickname]).wait()
        for f in data['files']:
            if os.path.exists(f):
                if os.path.exists(f):
                    os.unlink(f)
        self.cache_remove_attribute(guid, attribute)

    def apply(self, guid, ca, applier_func, *args, **kwargs):
        attribute = base64.b64encode(ca['name'].encode()).decode()
        # If the policy has changed, unapply, then apply new policy
        old_val = self.cache_get_attribute_value(guid, attribute)
        old_data = json.loads(old_val) if old_val is not None else {}
        templates = ['%s.%s' % (ca['name'], t.decode()) for t in get_supported_templates(ca['hostname'])] \
            if old_val is not None else []
        new_data = { 'templates': templates, **ca }
        if changed(new_data, old_data) or self.cache_get_apply_state() == GPOSTATE.ENFORCE:
            self.unapply(guid, attribute, old_val)
        # If policy is already applied and unchanged, skip application
        if old_val is not None and not changed(new_data, old_data) and \
                self.cache_get_apply_state() != GPOSTATE.ENFORCE:
            return

        # Apply the policy and log the changes
        data = applier_func(*args, **kwargs)
        self.cache_add_attribute(guid, attribute, data)

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list,
                             trust_dir=None, private_dir=None):
        if trust_dir is None:
            trust_dir = self.lp.cache_path('certs')
        if private_dir is None:
            private_dir = self.lp.private_path('certs')
        if not os.path.exists(trust_dir):
            os.mkdir(trust_dir, mode=0o755)
        if not os.path.exists(private_dir):
            os.mkdir(private_dir, mode=0o700)

        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for ca_cn_enc, data in settings[str(self)].items():
                    self.unapply(guid, ca_cn_enc, data)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = r'Software\Policies\Microsoft\Cryptography\AutoEnrollment'
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname == section and e.valuename == 'AEPolicy':
                        # This policy applies as specified in [MS-CAESO] 4.4.5.1
                        if e.data & 0x8000:
                            continue # The policy is disabled
                        enroll = e.data & 0x1 == 0x1
                        manage = e.data & 0x2 == 0x2
                        retrive_pending = e.data & 0x4 == 0x4
                        if enroll:
                            ca_names = self.__enroll(gpo.name,
                                                     pol_conf.entries,
                                                     trust_dir, private_dir)

                            # Cleanup any old CAs that have been removed
                            ca_attrs = [base64.b64encode(n.encode()).decode()
                                    for n in ca_names]
                            self.clean(gpo.name, keep=ca_attrs)
                        else:
                            # If enrollment has been disabled for this GPO,
                            # remove any existing policy
                            ca_attrs = \
                                self.cache_get_all_attribute_values(gpo.name)
                            self.clean(gpo.name, remove=list(ca_attrs.keys()))

    def __read_cep_data(self, guid, ldb, end_point_information,
                        trust_dir, private_dir):
        """Read CEP Data.

        [MS-CAESO] 4.4.5.3.2.4
        In this step autoenrollment initializes instances of the
        CertificateEnrollmentPolicy by accessing end points associated with CEP
        groups created in the previous step.
        """
        # For each group created in the previous step:
        for end_point_group in end_point_information:
            # Pick an arbitrary instance of the
            # CertificateEnrollmentPolicyEndPoint from the group
            e = end_point_group[0]

            # If this instance does not have the AutoEnrollmentEnabled flag set
            # in the EndPoint.Flags, continue with the next group.
            if not e['Flags'] & 0x10:
                continue

            # If the current group contains a
            # CertificateEnrollmentPolicyEndPoint instance with EndPoint.URI
            # equal to "LDAP":
            if any([e['URL'] == 'LDAP:' for e in end_point_group]):
                # Perform an LDAP search to read the value of the objectGuid
                # attribute of the root object of the forest root domain NC. If
                # any errors are encountered, continue with the next group.
                res = ldb.search('', SCOPE_BASE, '(objectClass=*)',
                                 ['rootDomainNamingContext'])
                if len(res) != 1:
                    continue
                res2 = ldb.search(res[0]['rootDomainNamingContext'][0],
                                  SCOPE_BASE, '(objectClass=*)',
                                  ['objectGUID'])
                if len(res2) != 1:
                    continue

                # Compare the value read in the previous step to the
                # EndPoint.PolicyId datum CertificateEnrollmentPolicyEndPoint
                # instance. If the values do not match, continue with the next
                # group.
                objectGUID = '{%s}' % \
                    str(ndr_unpack(misc.GUID, res2[0]['objectGUID'][0])).upper()
                if objectGUID != e['PolicyID']:
                    continue

            # For each CertificateEnrollmentPolicyEndPoint instance for that
            # group:
            ca_names = []
            for ca in end_point_group:
                # If EndPoint.URI equals "LDAP":
                if ca['URL'] == 'LDAP:':
                    # This is a basic configuration.
                    cas = fetch_certification_authorities(ldb)
                    for _ca in cas:
                        self.apply(guid, _ca, cert_enroll, _ca, ldb, trust_dir,
                                   private_dir)
                        ca_names.append(_ca['name'])
                # If EndPoint.URI starts with "HTTPS//":
                elif ca['URL'].lower().startswith('https://'):
                    self.apply(guid, ca, cert_enroll, ca, ldb, trust_dir,
                               private_dir, auth=ca['auth'])
                    ca_names.append(ca['name'])
                else:
                    edata = { 'endpoint': ca['URL'] }
                    log.error('Unrecognized endpoint', edata)
            return ca_names

    def __enroll(self, guid, entries, trust_dir, private_dir):
        url = 'ldap://%s' % get_dc_hostname(self.creds, self.lp)
        ldb = Ldb(url=url, session_info=system_session(),
                  lp=self.lp, credentials=self.creds)

        ca_names = []
        end_point_information = obtain_end_point_information(entries)
        if len(end_point_information) > 0:
            ca_names.extend(self.__read_cep_data(guid, ldb,
                                                 end_point_information,
                                                 trust_dir, private_dir))
        else:
            cas = fetch_certification_authorities(ldb)
            for ca in cas:
                self.apply(guid, ca, cert_enroll, ca, ldb, trust_dir,
                           private_dir)
                ca_names.append(ca['name'])
        return ca_names

    def rsop(self, gpo):
        output = {}
        pol_file = 'MACHINE/Registry.pol'
        section = r'Software\Policies\Microsoft\Cryptography\AutoEnrollment'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname == section and e.valuename == 'AEPolicy':
                    enroll = e.data & 0x1 == 0x1
                    if e.data & 0x8000 or not enroll:
                        continue
                    output['Auto Enrollment Policy'] = {}
                    url = 'ldap://%s' % get_dc_hostname(self.creds, self.lp)
                    ldb = Ldb(url=url, session_info=system_session(),
                              lp=self.lp, credentials=self.creds)
                    end_point_information = \
                        obtain_end_point_information(pol_conf.entries)
                    cas = fetch_certification_authorities(ldb)
                    if len(end_point_information) > 0:
                        cas2 = [ep for sl in end_point_information for ep in sl]
                        if any([ca['URL'] == 'LDAP:' for ca in cas2]):
                            cas.extend(cas2)
                        else:
                            cas = cas2
                    for ca in cas:
                        if 'URL' in ca and ca['URL'] == 'LDAP:':
                            continue
                        policy = 'Auto Enrollment Policy'
                        cn = ca['name']
                        if policy not in output:
                            output[policy] = {}
                        output[policy][cn] = {}
                        if 'cACertificate' in ca:
                            output[policy][cn]['CA Certificate'] = \
                                format_root_cert(ca['cACertificate']).decode()
                        output[policy][cn]['Auto Enrollment Server'] = \
                            ca['hostname']
                        supported_templates = \
                            get_supported_templates(ca['hostname'])
                        output[policy][cn]['Templates'] = \
                            [t.decode() for t in supported_templates]
        return output
