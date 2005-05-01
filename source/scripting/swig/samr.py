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

def call_fn(fn, pipe, args):
    """Wrap up a RPC call and throw an exception is an error was returned."""
    
    result = fn(pipe, args);

    if result & 0xc0000000L:
        raise dcerpc.NTSTATUS(result, dcerpc.nt_errstr(result));

    return result;
   
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

        call_fn(dcerpc.dcerpc_samr_Close, self.pipe, r)

        self.handle = None

    def QuerySecurity(self, sec_info = 7):

        r = dcerpc.samr_QuerySecurity()
        r.data_in.handle = self.handle
        r.data_in.sec_info = sec_info

        call_fn(dcerpc.dcerpc_samr_QuerySecurity, self.pipe, r)

        return r.data_out.sdbuf

    def SetSecurity(self, sdbuf, sec_info = 7):

        r = dcerpc.samr_SetSecurity()
        r.data_in.handle = self.handle
        r.data_in.sec_info = sec_info
        r.data_in.sdbuf = sdbuf

        call_fn(dcerpc.dcerpc_samr_SetSecurity, self.pipe, r)
        
class ConnectHandle(SamrHandle):

    def EnumDomains(self):

        r = dcerpc.samr_EnumDomains()
        r.data_in.connect_handle = self.handle
        r.data_in.resume_handle = 0
        r.data_in.buf_size = -1

        domains = []

        while 1:

            call_fn(dcerpc.dcerpc_samr_EnumDomains, self.pipe, r)

            for i in range(r.data_out.sam.count):
                domains.append(dcerpc.samr_SamEntry_array_getitem(
                    r.data_out.sam.entries, i).name.string)

            # TODO: Handle more entries here

            break

        return domains

    def LookupDomain(self, domain_name):

        r = dcerpc.samr_LookupDomain()
        r.data_in.connect_handle = self.handle
        r.data_in.domain_name = dcerpc.samr_String()
        r.data_in.domain_name.string = domain_name

        call_fn(dcerpc.dcerpc_samr_LookupDomain, self.pipe, r)

        return sid_to_string(r.data_out.sid);

    def OpenDomain(self, domain_sid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenDomain()
        r.data_in.connect_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.sid = string_to_sid(domain_sid)

        call_fn(dcerpc.dcerpc_samr_OpenDomain, self.pipe, r)

        return DomainHandle(self.pipe, r.data_out.domain_handle)

    def Shutdown(self):

        r = dcerpc.samr_Shutdown()
        r.data_in.connect_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_Shutdown, self.pipe, r)

    def GetDomPwInfo(self, domain_name):

        r = dcerpc.samr_GetDomPwInfo()
        r.data_in.domain_name = dcerpc.samr_String()
        r.data_in.domain_name.string = domain_name

        call_fn(dcerpc.dcerpc_samr_GetDomPwInfo, self.pipe, r)

        return r.data_out.info


    def SetBootKeyInformation(self, unknown1, unknown2, unknown3):
        
        r = dcerpc.samr_GetBootKeyInformation()
        r.data_in.connect_handle = self.handle
        r.data_in.unknown1 = unknown1
        r.data_in.unknown2 = unknown2
        r.data_in.unknown3 = unknown3

        call_fn(dcerpc.dcerpc_samr_SetBootKeyInformation, self.pipe, r)

class DomainHandle(SamrHandle):

    def QueryDomainInfo(self, level = 2):

        r = dcerpc.samr_QueryDomainInfo()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryDomainInfo, self.pipe, r)

        return getattr(r.data_out.info, 'info%d' % level)

    def QueryDomainInfo2(self, level = 2):

        r = dcerpc.samr_QueryDomainInfo2()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryDomainInfo2, self.pipe, r)

        return getattr(r.data_out.info, 'info%d' % level)       

    def SetDomainInfo(self, level, info):

        r = dcerpc.samr_SetDomainInfo()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level
        r.data_in.info = dcerpc.samr_DomainInfo()
        setattr(r.data_in.info, 'info%d' % level, info)

        call_fn(dcerpc.dcerpc_samr_SetDomainInfo, self.pipe, r)

    def EnumDomainGroups(self):

        r = dcerpc.samr_EnumDomainGroups()
        r.data_in.domain_handle = self.handle
        r.data_in.resume_handle = 0
        r.data_in.max_size = 1000

        call_fn(dcerpc.dcerpc_samr_EnumDomainGroups, self.pipe, r)

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

        call_fn(dcerpc.dcerpc_samr_EnumDomainAliases, self.pipe, r)

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

        call_fn(dcerpc.dcerpc_samr_EnumDomainUsers, self.pipe, r)

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

        call_fn(dcerpc.dcerpc_samr_CreateUser, self.pipe, r)

        return (r.data_out.user_handle,
                dcerpc.uint32_array_getitem(r.data_out.rid, 0))

    def CreateUser2(self, account_name, acct_flags = 0x00000010,
                    access_mask = 0x02000000):

        r = dcerpc.samr_CreateUser2()
        r.data_in.domain_handle = self.handle
        r.data_in.account_name = dcerpc.samr_String()
        r.data_in.account_name.string = account_name
        r.data_in.acct_flags = acct_flags
        r.data_in.access_mask = access_mask

        call_fn(dcerpc.dcerpc_samr_CreateUser2, self.pipe, r)

        return (r.data_out.user_handle,
                dcerpc.uint32_array_getitem(r.data_out.access_granted, 0),
                dcerpc.uint32_array_getitem(r.data_out.rid, 0))

    def OpenUser(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenUser()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        call_fn(dcerpc.dcerpc_samr_OpenUser, self.pipe, r)

        return UserHandle(self.pipe, r.data_out.user_handle)

    def OpenGroup(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenGroup()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        call_fn(dcerpc.dcerpc_samr_OpenGroup, self.pipe, r)

        return GroupHandle(self.pipe, r.data_out.group_handle)

    def OpenAlias(self, rid, access_mask = 0x02000000):

        r = dcerpc.samr_OpenAlias()
        r.data_in.domain_handle = self.handle
        r.data_in.access_mask = access_mask
        r.data_in.rid = rid

        call_fn(dcerpc.dcerpc_samr_OpenAlias, self.pipe, r)

        return AliasHandle(self.pipe, r.data_out.alias_handle)

    def CreateDomAlias(self, alias_name, access_mask = 0x02000000):

        r = dcerpc.samr_CreateDomAlias()
        r.data_in.domain_handle = self.handle
        r.data_in.alias_name = dcerpc.samr_String()
        r.data_in.alias_name.string = alias_name
        r.data_in.access_mask = access_mask

        call_fn(dcerpc.dcerpc_samr_CreateDomAlias, self.pipe, r)

        return (AliasHandle(self.pipe, r.data_out.alias_handle),
                r.data_out.rid)    

    def RidToSid(self, rid):

        r = dcerpc.samr_RidToSid()
        r.data_in.domain_handle = self.handle
        r.data_in.rid = rid

        call_fn(dcerpc.dcerpc_samr_RidToSid, self.pipe, r)

        return sid_to_string(r.data_out.sid)

    def RemoveMemberFromForeignDomain(self, sid):

        r = dcerpc.samr_RemoveMemberFromForeignDomain()
        r.data_in.domain_handle = self.handle
        r.data_in.sid = sid

        call_fn(dcerpc.dcerpc_samr_RemoveMemberFromForeignDomain, self.pipe, r)

    def LookupNames(self, names):

        r = dcerpc.samr_LookupNames()
        r.data_in.domain_handle = self.handle
        r.data_in.num_names = len(names)
        r.data_in.names = dcerpc.new_samr_String_array(len(names))

        for i in range(len(names)):
            s = dcerpc.samr_String()
            s.string = names[i]
            dcerpc.samr_String_array_setitem(r.data_in.names, i, s)

        call_fn(dcerpc.dcerpc_samr_LookupNames, self.pipe, r)

        return ([dcerpc.uint32_array_getitem(r.data_out.rids.ids, i)
                 for i in range(r.data_out.rids.count)],
                [dcerpc.uint32_array_getitem(r.data_out.types.ids, i)
                 for i in range(r.data_out.types.count)])

    def CreateDomainGroup(self, domain_name, access_mask = 0x02000000):

        r = dcerpc.samr_CreateDomainGroup()
        r.data_in.domain_handle = self.handle
        r.data_in.name = dcerpc.samr_String()
        r.data_in.name.string = domain_name
        r.data_in.access_mask = access_mask

        call_fn(dcerpc.dcerpc_samr_CreateDomainGroup, self.pipe, r)

    def GetAliasMembership(self, sids):

        r = dcerpc.samr_GetAliasMembership()
        r.data_in.domain_handle = self.handle
        r.data_in.sids = dcerpc.lsa_SidArray()
        r.data_in.sids.num_sids = len(sids)
        r.data_in.sids.sids = dcerpc.new_lsa_SidPtr_array(len(sids))

        for i in range(len(sids)):
            s = dcerpc.lsa_SidPtr()
            s.sid = string_to_sid(sids[i])
            dcerpc.lsa_SidPtr_array_setitem(r.data_in.sids.sids, i, s)

        call_fn(dcerpc.dcerpc_samr_GetAliasMembership, self.pipe, r)

        return [r.ids[x] for x in range(r.count)]

    def QueryDisplayInfo(self, level):

        # TODO: Handle more data returns

        r = dcerpc.samr_QueryDisplayInfo()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level
        r.data_in.start_idx = 0
        r.data_in.max_entries = 1000
        r.data_in.buf_size = -1

        call_fn(dcerpc.dcerpc_samr_QueryDisplayInfo, self.pipe, r)

        # TODO: Return a mapping of the various samr_DispInfo
        # structures here.

        return getattr(r.data_out.info, 'info%d' % level)
    
    def QueryDisplayInfo2(self, level):

        # TODO: Handle more data returns

        r = dcerpc.samr_QueryDisplayInfo2()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level
        r.data_in.start_idx = 0
        r.data_in.max_entries = 1000
        r.data_in.buf_size = -1

        call_fn(dcerpc.dcerpc_samr_QueryDisplayInfo2, self.pipe, r)

        # TODO: Return a mapping of the various samr_DispInfo
        # structures here.

        return getattr(r.data_out.info, 'info%d' % level)

    def QueryDisplayInfo3(self, level):

        # TODO: Handle more data returns

        r = dcerpc.samr_QueryDisplayInfo3()
        r.data_in.domain_handle = self.handle
        r.data_in.level = level
        r.data_in.start_idx = 0
        r.data_in.max_entries = 1000
        r.data_in.buf_size = -1

        call_fn(dcerpc.dcerpc_samr_QueryDisplayInfo3, self.pipe, r)

        # TODO: Return a mapping of the various samr_DispInfo
        # structures here.

        return getattr(r.data_out.info, 'info%d' % level)

    def GetBootKeyInformation(self):

        r = dcerpc.samr_GetBootKeyInformation()
        r.data_in.domain_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_GetBootKeyInformation, self.pipe, r)

        return r.data_out.unknown

    def SetBootKeyInformation(self):

        r = dcerpc.samr_GetBootKeyInformation()
        r.data_in.domain_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_GetBootKeyInformation, self.pipe, r)

    def TestPrivateFunctionsDomain(self):

        r = dcerpc.samr_TestPrivateFunctionsDomain()
        r.data_in.domain_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_TestPrivateFunctionsDomain, self.pipe, r)

class UserHandle(SamrHandle):

    def DeleteUser(self):

        r = dcerpc.samr_DeleteUser()
        r.data_in.user_handle = self.handle
        
        call_fn(dcerpc.dcerpc_samr_DeleteUser, self.pipe, r)

        self.handle = None

    def GetUserPwInfo(self):

        r = dcerpc.samr_GetUserPwInfo()
        r.data_in.user_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_GetUserPwInfo, self.pipe, r)

        return r.data_out.info

    def QueryUserInfo(self, level):

        r = dcerpc.samr_QueryUserInfo()
        r.data_in.user_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryUserInfo, self.pipe, r)

        return r.data_out.info

    def QueryUserInfo2(self, level):

        r = dcerpc.samr_QueryUserInfo2()
        r.data_in.user_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryUserInfo2, self.pipe, r)

        return r.data_out.info

    def GetGroupsForUser(self):

        r = dcerpc.samr_GetGroupsForUser()
        r.data_in.user_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_GetGroupsForUser, self.pipe, r)

        rid_types = [dcerpc.samr_RidType_array_getitem(r.data_out.rids.rid, x)
                     for x in range(r.data_out.rids.count)]

        return [(x.rid, x.type) for x in rid_types]

    def TestPrivateFunctionsUser(self):

        r = dcerpc.samr_TestPrivateFunctionsUser()
        r.data_in.user_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_TestPrivateFunctionsUser, self.pipe, r)
            
class GroupHandle(SamrHandle):

    def QueryGroupInfo(self, level):

        r = dcerpc.samr_QueryGroupInfo()
        r.data_in.group_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryGroupInfo, self.pipe, r)

        return r.data_out.info

    def SetGroupInfo(self, level, info):

        r = dcerpc.samr_SetGroupInfo()
        r.data_in.group_handle = self.handle
        r.data_in.level = level
        r.data_in.info = info

        call_fn(dcerpc.dcerpc_samr_SetGroupInfo, self.pipe, r)

    def QueryGroupMember(self):

        r = dcerpc.samr_QueryGroupMember()
        r.data_in.group_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_QueryGroupMember, self.pipe, r)

        return [(dcerpc.uint32_array_getitem(r.data_out.rids.rids, x),
                 dcerpc.uint32_array_getitem(r.data_out.rids.unknown, x))
                for x in range(r.data_out.rids.count)]
    
class AliasHandle(SamrHandle):

    def DeleteDomAlias(self):

        r = dcerpc.samr_DeleteDomAlias()
        r.data_in.alias_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_DeleteDomAlias, self.pipe, r)

        self.handle = None

    def QueryAliasInfo(self, level = 1):

        r = dcerpc.samr_QueryAliasInfo()
        r.data_in.alias_handle = self.handle
        r.data_in.level = level

        call_fn(dcerpc.dcerpc_samr_QueryAliasInfo, self.pipe, r)

        return r.data_out.info

    def SetAliasInfo(self, level, info):

        r = dcerpc.samr_SetAliasInfo()
        r.data_in.alias_handle = self.handle
        r.data_in.level = level
        r.data_in.info = info

        call_fn(dcerpc.dcerpc_samr_SetAliasInfo, self.pipe, r)

    def AddAliasMember(self, sid):

        r = dcerpc.samr_AddAliasMember()
        r.data_in.alias_handle = self.handle
        r.data_in.sid = string_to_sid(sid)

        call_fn(dcerpc.dcerpc_samr_AddAliasMember, self.pipe, r)

    def AddMultipleMembersToAlias(self, sids):

        r = dcerpc.samr_AddMultipleMembersToAlias()
        r.data_in.alias_handle = self.handle
        r.data_in.sids = dcerpc.lsa_SidArray()
        r.data_in.sids.num_sids = len(sids)
        r.data_in.sids.sids = dcerpc.new_lsa_SidPtr_array(len(sids))

        for i in range(len(sids)):
            s = dcerpc.lsa_SidPtr()
            s.sid = string_to_sid(sids[i])
            dcerpc.lsa_SidPtr_array_setitem(r.data_in.sids.sids, i, s)

        call_fn(dcerpc.dcerpc_samr_AddMultipleMembersToAlias, self.pipe, r)

    def GetMembersInAlias(self):

        r = dcerpc.samr_GetMembersInAlias()
        r.data_in.alias_handle = self.handle

        call_fn(dcerpc.dcerpc_samr_GetMembersInAlias, self.pipe, r)

        return [
            sid_to_string(
                dcerpc.lsa_SidPtr_array_getitem(r.data_out.sids.sids, x).sid)
            for x in range(r.data_out.sids.num_sids)]

def Connect(pipe, access_mask = 0x02000000):

    r = dcerpc.samr_Connect()
    r.data_in.system_name = dcerpc.new_uint16_array(1)
    dcerpc.uint16_array_setitem(r.data_in.system_name, 0, ord('\\'))
    r.data_in.access_mask = access_mask

    call_fn(dcerpc.dcerpc_samr_Connect, pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)

def Connect2(pipe, system_name = '', access_mask = 0x02000000):
    """Connect to the SAMR pipe."""

    r = dcerpc.samr_Connect2()
    r.data_in.system_name = system_name
    r.data_in.access_mask = access_mask

    call_fn(dcerpc.dcerpc_samr_Connect2, pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)

def Connect3(pipe, system_name = '', access_mask = 0x02000000):

    r = dcerpc.samr_Connect3()
    r.data_in.system_name = system_name
    r.data_in.unknown = 0
    r.data_in.access_mask = access_mask

    call_fn(dcerpc.dcerpc_samr_Connect3, pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)


def Connect4(pipe, system_name = '', access_mask = 0x02000000):

    r = dcerpc.samr_Connect4()
    r.data_in.system_name = system_name
    r.data_in.unknown = 0
    r.data_in.access_mask = access_mask

    call_fn(dcerpc.dcerpc_samr_Connect4, pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)

def Connect5(pipe, system_name = '', access_mask = 0x02000000):

    r = dcerpc.samr_Connect5()
    r.data_in.system_name = system_name
    r.data_in.access_mask = access_mask
    r.data_in.level = 1
    r.data_in.info = dcerpc.new_samr_ConnectInfo_array(1)
    r.data_in.info.unknown1 = 0
    r.data_in.info.unknown2 = 0

    call_fn(dcerpc.dcerpc_samr_Connect5, pipe, r)

    return ConnectHandle(pipe, r.data_out.connect_handle)
    
# AddGroupMember
# DeleteDomainGroup
# DeleteGroupMember
# SetMemberAttributesofGroup
# AddAliasMember
# DeleteAliasMember
# GetMembersinAlias
# SetUserInfo
# ChangePasswordUser
# GetDisplayEnumerationIndex
# RemoveMemberFromForeignDomain
# GetDisplayEnumerationIndex2
# RemoveMultipleMembersFromAlias
# OemChangePasswordUser2
# ChangePasswordUser2
# SetUserInfo2
# ChangePasswordUser3
# SetDsrmPassword
# ValidatePassword
