import dcerpc

def sid_to_string(sid):
    """Convert a Python dictionary SID to a string SID."""

    result = 'S-%d' % sid.sid_rev_num

    result = result + '-%u' % \
             (dcerpc.uint8_array_getitem(sid.id_auth, 5) +
              (dcerpc.uint8_array_getitem(sid.id_auth, 4) << 8) + 
              (dcerpc.uint8_array_getitem(sid.id_auth, 3) << 16) +
              (dcerpc.uint8_array_getitem(sid.id_auth, 2) << 24))
    
    for i in range(0, sid.num_auths):
        result = result + '-%u' % \
                 dcerpc.uint32_array_getitem(sid.sub_auths, i)

    return result


def string_to_sid(string):
    """Convert a string SID to a Python dictionary SID.  Throws a
    ValueError if the SID string was badly formed."""

    if string[0] != 'S':
        raise ValueError('Bad SID format')

    string = string[1:]

    import re

    match = re.match('-\d+', string)

    if not match:
        raise ValueError('Bad SID format')

    try:
        sid_rev_num = int(string[match.start()+1:match.end()])
    except ValueError:
        raise ValueError('Bad SID format')

    string = string[match.end():]

    match = re.match('-\d+', string)

    if not match:
        raise ValueError('Bad SID format')

    try:
        ia = int(string[match.start()+1:match.end()])
    except ValueError:
        raise ValueError('Bad SID format')

    string = string[match.end():]

    id_auth = [0, 0, (ia >> 24) & 0xff, (ia >> 16) & 0xff,
               (ia >> 8) & 0xff, ia & 0xff]

    num_auths = 0
    sub_auths = []
    
    while len(string):

        match = re.match('-\d+', string)

        if not match:
            raise ValueError('Bad SID format')

        try:
            sa = int(string[match.start() + 1 : match.end()])
        except ValueError:
            raise ValueError('Bad SID format')

        num_auths = num_auths + 1
        sub_auths.append(int(sa))

        string = string[match.end():]

    sid = dcerpc.dom_sid()
    sid.sid_rev_num = sid_rev_num
    sid.id_auth = dcerpc.new_uint8_array(6)
    for i in range(6):
        dcerpc.uint8_array_setitem(sid.id_auth, i, id_auth[i])
    sid.num_auths = num_auths
    sid.sub_auths = dcerpc.new_uint32_array(num_auths)
    for i in range(num_auths):
        dcerpc.uint32_array_setitem(sid.sub_auths, i, sub_auths[i])

    return sid


class SamrHandle:

    def __init__(self, pipe, handle):

        self.pipe = pipe
        self.handle = handle

    def __del__(self):

        if self.handle is not None:
            self.Close()

    def Close(self):
                    
        r = dcerpc.samr_Close()
        r.data_in.handle = self.handle

        dcerpc.dcerpc_samr_Close(self.pipe, r)

        self.handle = None

    def QuerySecurity(self, sec_info = 7):

        r = dcerpc.samr_QuerySecurity()
        r.data_in.handle = self.handle
        r.data_in.sec_info = sec_info

        result = dcerpc.dcerpc_samr_QuerySecurity(self.pipe, r)

        return r.data_out.sdbuf.sd

    def SetSecurity(self, sec_info = 7):

        r = dcerpc.samr_SetSecurity()
        r.data_in.handle = self.handle
        r.data_in.sec_info = sec_info


class ConnectHandle(SamrHandle):

    def EnumDomains(self):

        r = dcerpc.samr_EnumDomains()
        r.data_in.connect_handle = self.handle
        r.data_in.resume_handle = 1
        r.data_in.buf_size = -1

        domains = []

        while 1:

            result = dcerpc.dcerpc_samr_EnumDomains(self.pipe, r)

            for i in range(r.data_out.sam.count):
                domains.append(dcerpc.samr_SamEntry_array_getitem(
                    r.data_out.sam.entries, i).name.string)

            # TODO: Handle more entries here

            break

        return domains

    def LookupDomain(self, domain_name):

        r = dcerpc.samr_LookupDomain()
        r.data_in.connect_handle = self.handle
        r.data_in.domain = dcerpc.samr_String()
        r.data_in.domain.string = domain_name

        result = dcerpc.dcerpc_samr_LookupDomain(self.pipe, r)

        return sid_to_string(r.data_out.sid);

    def OpenDomain(self, domain_sid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenDomain()
        r.data_in.connect_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.sid = string_to_sid(domain_sid)

        result = dcerpc.dcerpc_samr_OpenDomain(self.pipe, r)

        return DomainHandle(self.pipe, r.data_out.domain_handle)

    def Shutdown(self):

        r = dcerpc.samr_Shutdown()
        r.data_in.connect_handle = self.handle

        result = dcerpc.dcerpc_samr_Shutdown(self.pipe, r)


class DomainHandle(SamrHandle):

    def QueryDomainInfo(self, level = 2):

        r = dcerpc.samr_QueryDomainInfo()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level

        result = dcerpc.dcerpc_samr_QueryDomainInfo(self.pipe, r)

        return getattr(r.data_out.info, 'info%d' % level)

    def QueryDomainInfo2(self, level = 2):

        r = dcerpc.samr_QueryDomainInfo2()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level

        result = dcerpc.dcerpc_samr_QueryDomainInfo2(self.pipe, r)

        return getattr(r.data_out.info, 'info%d' % level)       

    def EnumDomainGroups(self):

        r = dcerpc.samr_EnumDomainGroups()
        r.data_in.domain_handle = self.handle
        r.data_in.resume_handle = 0
        r.data_in.max_size = 1000

        result = dcerpc.dcerpc_samr_EnumDomainGroups(self.pipe, r)

        groups = []

        if r.data_out.sam.entries:
            for i in range(r.data_out.sam.count):
                groups.append(dcerpc.samr_SamEntry_array_getitem(
                    r.data_out.sam.entries, i).name.string)

        return groups

    def EnumDomainAliases(self):

        r = dcerpc.samr_EnumDomainAliases()
        r.data_in.domain_handle = self.handle
        r.data_in.resume_handle = 0
        # acct_flags in SamrEnumerateAliasesInDomain has probably
        # no meaning so use 0xffffffff like W2K
        r.data_in.acct_flags = 0xffffffffL

        result = dcerpc.dcerpc_samr_EnumDomainAliases(self.pipe, r)

        aliases = []

        if r.data_out.sam.entries:
            for i in range(r.data_out.sam.count):
                aliases.append(dcerpc.samr_SamEntry_array_getitem(
                    r.data_out.sam.entries, i).name.string)

        return aliases

    def EnumDomainUsers(self, user_account_flags = 16):

        r = dcerpc.samr_EnumDomainUsers()
        r.data_in.domain_handle = self.handle
        r.data_in.resume_handle = 0
        r.data_in.acct_flags = user_account_flags
        r.data_in.max_size = 1000

        result = dcerpc.dcerpc_samr_EnumDomainUsers(self.pipe, r)

        users = []

        if r.data_out.sam.entries:
            for i in range(r.data_out.sam.count):
                users.append(dcerpc.samr_SamEntry_array_getitem(
                    r.data_out.sam.entries, i).name.string)

        return users

    def CreateUser(self, account_name, access_mask = 0x02000000):

        r = dcerpc.samr_CreateUser()
        r.data_in.domain_handle = self.handle
        r.data_in.account_name = dcerpc.samr_String()
        r.data_in.account_name.string = account_name
        r.data_in.access_mask = access_mask

        result = dcerpc.dcerpc_samr_CreateUser(self.pipe, r)

        return (r.data_out.user_handle,
                dcerpc.uint32_array_getitem(r.data_out.rid, 0))
        
    def OpenUser(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenUser()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        result = dcerpc.dcerpc_samr_OpenUser(self.pipe, r)

        return UserHandle(pipe, r.data_out.user_handle)

    def OpenGroup(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenGroup()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        result = dcerpc.dcerpc_samr_OpenGroup(self.pipe, r)

        return GroupHandle(pipe, r.data_out.group_handle)

    def OpenAlias(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenAlias()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        result = dcerpc.dcerpc_samr_OpenAlias(self.pipe, r)

        return AliasHandle(pipe, r.data_out.group_handle)

    def RidToSid(self, rid):

        r = dcerpc.samr_RidToSid()
        r.data_in.domain_handle = self.handle

        result = dcerpc.dcerpc_samr_RidToSid(self.pipe, r)

        return sid_to_string(r.data_out.sid)


class UserHandle(SamrHandle):
    pass
    

class GroupHandle(SamrHandle):
    pass
    

class AliasHandle(SamrHandle):
    pass
    

def Connect2(pipe, system_name = '', access_mask = 0x02000000):
    """Connect to the SAMR pipe."""

    r = dcerpc.samr_Connect2()
    r.data_in.system_name = system_name
    r.data_in.access_mask = access_mask

    result = dcerpc.dcerpc_samr_Connect2(pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)

# CreateDomainGroup
# CreateDomAlias
# GetAliasMembership
# LookupNames
# QueryGroupInfo
# SetGroupInfo
# AddGroupMember
# DeleteDomainGroup
# DeleteGroupMember
# QueryGroupMember
# SetMemberAttributesofGroup
# QueryAliasInfo
# SetAliasInfo
# DeleteDomAlias
# AddAliasMember
# DeleteAliasMember
# GetMembersinAlias
# DeleteUser
# QueryUserInfo
# SetUserInfo
# ChangePasswordUser
# GetGroupsForUser
# QueryDisplayInfo
# GetDisplayEnumerationIndex
# TestPrivateFunctionsDomain
# TestPrivateFunctionsUser
# GetUserPwInfo
# RemoveMemberFromForeignDomain
# QueryDomainInfo2
# QueryUserInfo2
# QueryDisplayInfo2
# GetDisplayEnumerationIndex2
# CreateUser2
# QueryDisplayInfo3
# AddMultipleMembersToAlias
# RemoveMultipleMembersFromAlias
# OemChangePasswordUser2
# ChangePasswordUser2
# GetDomPwInfo
# Connect
# SetUserInfo2
# SetBootKeyInformation
# GetBootKeyInformation
# Connect3
# Connect4
# ChangePasswordUser3
# Connect5
# SetDsrmPassword
# ValidatePassword
