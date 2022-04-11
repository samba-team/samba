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
from samba.gpclass import gp_pol_ext
from samba import Ldb
from ldb import SCOPE_SUBTREE
from samba.auth import system_session
from samba.gpclass import get_dc_hostname
import base64
from tempfile import NamedTemporaryFile
from shutil import move, which
from subprocess import Popen, PIPE
import re
from glob import glob
import json
from samba.gp.util.logging import log

cert_wrap = b"""
-----BEGIN CERTIFICATE-----
%s
-----END CERTIFICATE-----"""
global_trust_dir = '/etc/pki/trust/anchors'

'''
Initializing CAs
[MS-CAESO] 4.4.5.3.1.2
'''
def fetch_certification_authorities(ldb):
    result = []
    basedn = ldb.get_default_basedn()
    # Autoenrollment MUST do an LDAP search for the CA information
    # (pKIEnrollmentService) objects under the following container:
    dn = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,%s' % basedn
    attrs = ['cACertificate', 'cn', 'certificateTemplates', 'dNSHostName',
             'msPKI-Enrollment-Servers']
    expr = '(objectClass=pKIEnrollmentService)'
    res = ldb.search(dn, SCOPE_SUBTREE, expr, attrs)
    if len(res) == 0:
        return result
    for es in res:
        data = dict(es)
        result.append(data)
    return result

def fetch_template_attrs(ldb, name, attrs=['msPKI-Minimal-Key-Size']):
    basedn = ldb.get_default_basedn()
    dn = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,%s' % basedn
    expr = '(cn=%s)' % name
    res = ldb.search(dn, SCOPE_SUBTREE, expr, attrs)
    if len(res) == 1 and 'msPKI-Minimal-Key-Size' in res[0]:
        return dict(res[0])
    else:
        return {'msPKI-Minimal-Key-Size': ['2048']}

def format_root_cert(cert):
    cert = base64.b64encode(cert)
    return cert_wrap % re.sub(b"(.{64})", b"\\1\n", cert, 0, re.DOTALL)

def find_cepces_submit():
    certmonger_dirs = [os.environ.get("PATH"), '/usr/lib/certmonger',
                       '/usr/libexec/certmonger']
    return which('cepces-submit', path=':'.join(certmonger_dirs))

def get_supported_templates(server):
    cepces_submit = find_cepces_submit()
    if os.path.exists(cepces_submit):
        env = os.environ
        env['CERTMONGER_OPERATION'] = 'GET-SUPPORTED-TEMPLATES'
        p = Popen([cepces_submit, '--server=%s' % server, '--auth=Kerberos'],
                       env=env, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            data = { 'Error': err.decode() }
            log.error('Failed to fetch the list of supported templates.', data)
        return out.strip().split()
    return []

def cert_enroll(ca, ldb, trust_dir, private_dir, auth='Kerberos'):
    # Install the root certificate chain
    data = {'files': [], 'templates': []}
    sscep = which('sscep')
    if sscep is not None:
        url = 'http://%s/CertSrv/mscep/mscep.dll/pkiclient.exe?' % \
            ca['dNSHostName'][0]
        root_cert = os.path.join(trust_dir, '%s.crt' % ca['cn'])
        ret = Popen([sscep, 'getca', '-F', 'sha1', '-c',
                     root_cert, '-u', url]).wait()
        if ret != 0:
            log.warn('sscep failed to fetch the root certificate chain.')
            log.warn('Ensure you have installed and configured the' +
                     ' Network Device Enrollment Service.')
        root_certs = glob('%s*' % root_cert)
        data['files'].extend(root_certs)
        for src in root_certs:
            # Symlink the certs to global trust dir
            dst = os.path.join(global_trust_dir, os.path.basename(src))
            try:
                os.symlink(src, dst)
                data['files'].append(dst)
            except PermissionError:
                log.warn('Failed to symlink root certificate to the' +
                         ' admin trust anchors')
            except FileNotFoundError:
                log.warn('Failed to symlink root certificate to the' +
                         ' admin trust anchors.' +
                         ' The directory was not found', global_trust_dir)
            except FileExistsError:
                # If we're simply downloading a renewed cert, the symlink
                # already exists. Ignore the FileExistsError. Preserve the
                # existing symlink in the unapply data.
                data['files'].append(dst)
    else:
        log.warn('sscep is not installed, which prevents the installation' +
                 ' of the root certificate chain.')
    update = which('update-ca-certificates')
    if update is not None:
        Popen([update]).wait()
    # Setup Certificate Auto Enrollment
    getcert = which('getcert')
    cepces_submit = find_cepces_submit()
    if getcert is not None and os.path.exists(cepces_submit):
        p = Popen([getcert, 'add-ca', '-c', ca['cn'][0], '-e',
                  '%s --server=%s --auth=Kerberos' % (cepces_submit,
                  ca['dNSHostName'][0])],
                  stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        log.debug(out.decode())
        if p.returncode != 0:
            data = { 'Error': err.decode(), 'CA': ca['cn'][0] }
            log.error('Failed to add Certificate Authority', data)
        supported_templates = get_supported_templates(ca['dNSHostName'][0])
        for template in supported_templates:
            attrs = fetch_template_attrs(ldb, template)
            nickname = '%s.%s' % (ca['cn'][0], template.decode())
            keyfile = os.path.join(private_dir, '%s.key' % nickname)
            certfile = os.path.join(trust_dir, '%s.crt' % nickname)
            p = Popen([getcert, 'request', '-c', ca['cn'][0],
                       '-T', template.decode(),
                       '-I', nickname, '-k', keyfile, '-f', certfile,
                       '-g', attrs['msPKI-Minimal-Key-Size'][0]],
                       stdout=PIPE, stderr=PIPE)
            out, err = p.communicate()
            log.debug(out.decode())
            if p.returncode != 0:
                data = { 'Error': err.decode(), 'Certificate': nickname }
                log.error('Failed to request certificate', data)
            data['files'].extend([keyfile, certfile])
            data['templates'].append(nickname)
        if update is not None:
            Popen([update]).wait()
    else:
        log.warn('certmonger and cepces must be installed for ' +
                 'certificate auto enrollment to work')
    return json.dumps(data)

class gp_cert_auto_enroll_ext(gp_pol_ext):
    def __str__(self):
        return 'Cryptography\AutoEnrollment'

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
            self.gp_db.set_guid(guid)
            if str(self) in settings:
                for ca_cn_enc, data in settings[str(self)].items():
                    ca_cn = base64.b64decode(ca_cn_enc)
                    data = json.loads(data)
                    getcert = which('getcert')
                    if getcert is not None:
                        Popen([getcert, 'remove-ca', '-c', ca_cn]).wait()
                        for nickname in data['templates']:
                            Popen([getcert, 'stop-tracking',
                                   '-i', nickname]).wait()
                    for f in data['files']:
                        if os.path.exists(f):
                            os.unlink(f)
                    self.gp_db.delete(str(self), ca_cn_enc)
            self.gp_db.commit()

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                section = 'Software\Policies\Microsoft\Cryptography\AutoEnrollment'
                self.gp_db.set_guid(gpo.name)
                pol_file = 'MACHINE/Registry.pol'
                path = os.path.join(gpo.file_sys_path, pol_file)
                pol_conf = self.parse(path)
                if not pol_conf:
                    continue
                for e in pol_conf.entries:
                    if e.keyname == section and e.valuename == 'AEPolicy':
                        # This policy applies as specified in [MS-CAESO] 4.4.5.1
                        if e.data == 0x8000:
                            continue # The policy is disabled
                        enroll = e.data & 0x1 == 1
                        manage = e.data & 0x2 == 1
                        retrive_pending = e.data & 0x4 == 1
                        if enroll:
                            url = 'ldap://%s' % get_dc_hostname(self.creds,
                                                                self.lp)
                            ldb = Ldb(url=url, session_info=system_session(),
                                      lp=self.lp, credentials=self.creds)
                            cas = fetch_certification_authorities(ldb)
                            for ca in cas:
                                data = cert_enroll(ca, ldb, trust_dir, private_dir)
                                self.gp_db.store(str(self),
                                     base64.b64encode(ca['cn'][0]).decode(),
                                     data)
                        self.gp_db.commit()

    def rsop(self, gpo):
        output = {}
        pol_file = 'MACHINE/Registry.pol'
        section = 'Software\Policies\Microsoft\Cryptography\AutoEnrollment'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, pol_file)
            pol_conf = self.parse(path)
            if not pol_conf:
                return output
            for e in pol_conf.entries:
                if e.keyname == section and e.valuename == 'AEPolicy':
                    enroll = e.data & 0x1 == 1
                    if e.data == 0x8000 or not enroll:
                        continue
                    output['Auto Enrollment Policy'] = {}
                    url = 'ldap://%s' % get_dc_hostname(self.creds, self.lp)
                    ldb = Ldb(url=url, session_info=system_session(),
                              lp=self.lp, credentials=self.creds)
                    cas = fetch_certification_authorities(ldb)
                    for ca in cas:
                        policy = 'Auto Enrollment Policy'
                        cn = ca['cn'][0]
                        output[policy][cn] = {}
                        output[policy][cn]['CA Certificate'] = \
                            format_root_cert(ca['cACertificate'][0]).decode()
                        output[policy][cn]['Auto Enrollment Server'] = \
                            ca['dNSHostName'][0]
                        supported_templates = \
                            get_supported_templates(ca['dNSHostName'][0])
                        output[policy][cn]['Templates'] = \
                            [t.decode() for t in supported_templates]
        return output
