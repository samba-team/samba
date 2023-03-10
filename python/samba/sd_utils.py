# Utility methods for security descriptor manipulation
#
# Copyright Nadezhda Ivanova 2010 <nivanova@samba.org>
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

"""Utility methods for security descriptor manipulation."""

import samba
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, SCOPE_BASE
from samba.ndr import ndr_pack, ndr_unpack, ndr_deepcopy
from samba.dcerpc import security
from samba.ntstatus import (
    NT_STATUS_OBJECT_NAME_NOT_FOUND,
)


class SDUtils(object):
    """Some utilities for manipulation of security descriptors on objects."""

    def __init__(self, samdb):
        self.ldb = samdb
        self.domain_sid = security.dom_sid(self.ldb.get_domain_sid())

    def modify_sd_on_dn(self, object_dn, sd, controls=None):
        """Modify security descriptor using either SDDL string
            or security.descriptor object
        """
        m = Message()
        if isinstance(object_dn, Dn):
            m.dn = object_dn
        else:
            m.dn = Dn(self.ldb, object_dn)

        assert(isinstance(sd, str) or isinstance(sd, security.descriptor))
        if isinstance(sd, str):
            tmp_desc = security.descriptor.from_sddl(sd, self.domain_sid)
        elif isinstance(sd, security.descriptor):
            tmp_desc = sd

        m["nTSecurityDescriptor"] = MessageElement(ndr_pack(tmp_desc),
                                                   FLAG_MOD_REPLACE,
                                                   "nTSecurityDescriptor")
        self.ldb.modify(m, controls)

    def read_sd_on_dn(self, object_dn, controls=None):
        res = self.ldb.search(object_dn, SCOPE_BASE, None,
                              ["nTSecurityDescriptor"], controls=controls)
        desc = res[0]["nTSecurityDescriptor"][0]
        return ndr_unpack(security.descriptor, desc)

    def get_object_sid(self, object_dn):
        res = self.ldb.search(object_dn)
        return ndr_unpack(security.dom_sid, res[0]["objectSid"][0])

    def update_aces_in_dacl(self, dn, del_aces=None, add_aces=None,
                            sddl_attr=None, controls=None):
        if del_aces is None:
            del_aces=[]
        if add_aces is None:
            add_aces=[]

        def ace_from_sddl(ace_sddl):
            ace_sd = security.descriptor.from_sddl("D:" + ace_sddl, self.domain_sid)
            assert(len(ace_sd.dacl.aces)==1)
            return ace_sd.dacl.aces[0]

        if sddl_attr is None:
            if controls is None:
                controls=["sd_flags:1:%d" % security.SECINFO_DACL]
            sd = self.read_sd_on_dn(dn, controls=controls)
            if not sd.type & security.SEC_DESC_DACL_PROTECTED:
                # if the DACL is not protected remove all
                # inherited aces, as they will be re-inherited
                # on the server, we need a ndr_deepcopy in order
                # to avoid reference problems while deleting
                # the aces while looping over them
                dacl_copy = ndr_deepcopy(sd.dacl)
                for ace in dacl_copy.aces:
                    if ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE:
                        try:
                            sd.dacl_del_ace(ace)
                        except samba.NTSTATUSError as err:
                            if err.args[0] != NT_STATUS_OBJECT_NAME_NOT_FOUND:
                                raise err
                            # dacl_del_ace may remove more than
                            # one ace, so we may not find it anymore
                            pass
        else:
            if controls is None:
                controls=[]
            res = self.ldb.search(dn, SCOPE_BASE, None,
                                  [sddl_attr], controls=controls)
            old_sddl = str(res[0][sddl_attr][0])
            sd = security.descriptor.from_sddl(old_sddl, self.domain_sid)

        num_changes = 0
        del_ignored = []
        add_ignored = []
        inherited_ignored = []

        for ace in del_aces:
            if isinstance(ace, str):
                ace = ace_from_sddl(ace)
            assert(isinstance(ace, security.ace))

            if ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE:
                inherited_ignored.append(ace)
                continue

            if ace not in sd.dacl.aces:
                del_ignored.append(ace)
                continue

            sd.dacl_del_ace(ace)
            num_changes += 1

        for ace in add_aces:
            add_idx = -1
            if isinstance(ace, dict):
                if "idx" in ace:
                    add_idx = ace["idx"]
                ace = ace["ace"]
            if isinstance(ace, str):
                ace = ace_from_sddl(ace)
            assert(isinstance(ace, security.ace))

            if ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE:
                inherited_ignored.append(ace)
                continue

            if ace in sd.dacl.aces:
                add_ignored.append(ace)
                continue

            sd.dacl_add(ace, add_idx)
            num_changes += 1

        if num_changes == 0:
            return del_ignored, add_ignored, inherited_ignored

        if sddl_attr is None:
            self.modify_sd_on_dn(dn, sd, controls=controls)
        else:
            new_sddl = sd.as_sddl(self.domain_sid)
            m = Message()
            m.dn = dn
            m[sddl_attr] = MessageElement(new_sddl.encode('ascii'),
                                          FLAG_MOD_REPLACE,
                                          sddl_attr)
            self.ldb.modify(m, controls=controls)

        return del_ignored, add_ignored, inherited_ignored

    def dacl_add_ace(self, object_dn, ace):
        """Add an ACE (or more) to an objects security descriptor
        """
        ace_sd = security.descriptor.from_sddl("D:" + ace, self.domain_sid)
        add_aces = []
        add_idx = 0
        for ace in ace_sd.dacl.aces:
            add_aces.append({"idx": add_idx, "ace": ace})
            add_idx += 1
        _,_,_ = self.update_aces_in_dacl(object_dn, add_aces=add_aces,
                                         controls=["show_deleted:1"])

    def get_sd_as_sddl(self, object_dn, controls=None):
        """Return object nTSecutiryDescriptor in SDDL format
        """
        if controls is None:
            controls = []
        desc = self.read_sd_on_dn(object_dn, controls + ["show_deleted:1"])
        return desc.as_sddl(self.domain_sid)
