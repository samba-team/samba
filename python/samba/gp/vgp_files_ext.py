# vgp_files_ext samba gpo policy
# Copyright (C) David Mulder <dmulder@suse.com> 2020
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

import os, pwd, grp
from samba.gp.gpclass import gp_xml_ext, check_safe_path, gp_file_applier
from tempfile import NamedTemporaryFile
from shutil import copyfile, move
from samba.gp.util.logging import log

def calc_mode(entry):
    mode = 0o000
    for permissions in entry.findall('permissions'):
        ptype = permissions.get('type')
        if ptype == 'user':
            if permissions.find('read') is not None:
                mode |= 0o400
            if permissions.find('write') is not None:
                mode |= 0o200
            if permissions.find('execute') is not None:
                mode |= 0o100
        elif ptype == 'group':
            if permissions.find('read') is not None:
                mode |= 0o040
            if permissions.find('write') is not None:
                mode |= 0o020
            if permissions.find('execute') is not None:
                mode |= 0o010
        elif ptype == 'other':
            if permissions.find('read') is not None:
                mode |= 0o004
            if permissions.find('write') is not None:
                mode |= 0o002
            if permissions.find('execute') is not None:
                mode |= 0o001
    return mode

def stat_from_mode(mode):
    stat = '-'
    for i in range(6, -1, -3):
        mask = {0o4: 'r', 0o2: 'w', 0o1: 'x'}
        for x in mask.keys():
            if mode & (x << i):
                stat += mask[x]
            else:
                stat += '-'
    return stat

def source_file_change(fname):
    if os.path.exists(fname):
        return b'%d' % os.stat(fname).st_ctime

class vgp_files_ext(gp_xml_ext, gp_file_applier):
    def __str__(self):
        return 'VGP/Unix Settings/Files'

    def process_group_policy(self, deleted_gpo_list, changed_gpo_list):
        for guid, settings in deleted_gpo_list:
            if str(self) in settings:
                for attribute, _ in settings[str(self)].items():
                    self.unapply(guid, attribute, attribute)

        for gpo in changed_gpo_list:
            if gpo.file_sys_path:
                self.gp_db.set_guid(gpo.name)
                xml = 'MACHINE/VGP/VTLA/Unix/Files/manifest.xml'
                path = os.path.join(gpo.file_sys_path, xml)
                xml_conf = self.parse(path)
                if not xml_conf:
                    continue
                policy = xml_conf.find('policysetting')
                data = policy.find('data')
                for entry in data.findall('file_properties'):
                    local_path = self.lp.cache_path('gpo_cache')
                    source = entry.find('source').text
                    source_file = os.path.join(local_path,
                        os.path.dirname(check_safe_path(path)).upper(),
                                        source.upper())
                    if not os.path.exists(source_file):
                        log.warn('Source file does not exist', source_file)
                        continue
                    target = entry.find('target').text
                    user = entry.find('user').text
                    group = entry.find('group').text
                    mode = calc_mode(entry)

                    # The attribute is simply the target file.
                    attribute = target
                    # The value hash is generated from the source file last
                    # change stamp, the user, the group, and the mode, ensuring
                    # any changes to this GPO will cause the file to be
                    # rewritten.
                    value_hash = self.generate_value_hash(
                            source_file_change(source_file),
                            user, group, b'%d' % mode)
                    def applier_func(source_file, target, user, group, mode):
                        with NamedTemporaryFile(dir=os.path.dirname(target),
                                                delete=False) as f:
                            copyfile(source_file, f.name)
                            os.chown(f.name, pwd.getpwnam(user).pw_uid,
                                     grp.getgrnam(group).gr_gid)
                            os.chmod(f.name, mode)
                            move(f.name, target)
                        return [target]
                    self.apply(gpo.name, attribute, value_hash, applier_func,
                               source_file, target, user, group, mode)

    def rsop(self, gpo):
        output = {}
        xml = 'MACHINE/VGP/VTLA/Unix/Files/manifest.xml'
        if gpo.file_sys_path:
            path = os.path.join(gpo.file_sys_path, xml)
            xml_conf = self.parse(path)
            if not xml_conf:
                return output
            policy = xml_conf.find('policysetting')
            data = policy.find('data')
            for entry in data.findall('file_properties'):
                source = entry.find('source').text
                target = entry.find('target').text
                user = entry.find('user').text
                group = entry.find('group').text
                mode = calc_mode(entry)
                p = '%s\t%s\t%s\t%s -> %s' % \
                    (stat_from_mode(mode), user, group, target, source)
                if str(self) not in output.keys():
                    output[str(self)] = []
                output[str(self)].append(p)
        return output
