import dcerpc

def sid_to_string(sid):
    """Convert a Python dictionary SID to a string SID."""

    result = 'S-%d' % sid['sid_rev_num']

    ia = sid['id_auth']
    
    result = result + '-%u' % (ia[5] + (ia[4] << 8) + (ia[3] << 16) + \
             (ia[2] << 24))
    
    for i in range(0, sid['num_auths']):
        result = result + '-%u' % sid['sub_auths'][i]

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
    
    return {'sid_rev_num': sid_rev_num, 'id_auth': id_auth,
            'num_auths': num_auths, 'sub_auths': sub_auths}


class SamrHandle:

    def __init__(self, pipe, handle):

        self.pipe = pipe
        self.handle = handle

    def __del__(self):

        r = {}
        r['handle'] = self.handle

        dcerpc.samr_Close(self.pipe, r)


class ConnectHandle(SamrHandle):

    def EnumDomains(self):

        r = {}
        r['connect_handle'] = self.handle
        r['resume_handle'] = 0
        r['buf_size'] = -1

        domains = []

        while 1:

            result = dcerpc.samr_EnumDomains(self.pipe, r)

            domains = domains + result['sam']['entries']

            if result['result'] == dcerpc.STATUS_MORE_ENTRIES:
                r['resume_handle'] = result['resume_handle']
                continue

            break

        return map(lambda x: x['name']['name'], domains)

    def LookupDomain(self, domain_name):

        r = {}
        r['connect_handle'] = self.handle
        r['domain'] = {}
        r['domain']['name_len'] = 0
        r['domain']['name_size'] = 0
        r['domain']['name'] = domain_name

        result = dcerpc.samr_LookupDomain(self.pipe, r)

        return sid_to_string(result['sid'])

    def OpenDomain(self, domain_sid, access_mask = 0x02000000):

        r = {}
        r['connect_handle'] = self.handle
        r['access_mask'] = access_mask
        r['sid'] = string_to_sid(domain_sid)

        result = dcerpc.samr_OpenDomain(self.pipe, r)

        return DomainHandle(self.pipe, result['domain_handle'])


class DomainHandle(SamrHandle):

    def QueryDomainInfo(self, level = 2):

        r = {}
        r['domain_handle'] = self.handle
        r['level'] = level

        result = dcerpc.samr_QueryDomainInfo(self.pipe, r)

        return result

    def QueryDomainInfo2(self, level = 2):

        r = {}
        r['domain_handle'] = self.handle
        r['level'] = level

        result = dcerpc.samr_QueryDomainInfo2(self.pipe, r)

        return result

    def EnumDomainGroups(self):

        r = {}
        r['domain_handle'] = self.handle
        r['resume_handle'] = 0
        r['max_size'] = 1000

        result = dcerpc.samr_EnumDomainGroups(self.pipe, r)

        return result

    def EnumDomainAliases(self):

        r = {}
        r['domain_handle'] = self.handle
        r['resume_handle'] = 0
        # acct_flags in SamrEnumerateAliasesInDomain has probably
        # no meaning so use 0xffffffff like W2K
        r['acct_flags'] = 0xffffffff
        r['max_size'] = 1000

        result = dcerpc.samr_EnumDomainAliases(self.pipe, r)

        return result

    def EnumDomainUsers(self, user_account_flags = 16):

        r = {}
        r['domain_handle'] = self.handle
        r['resume_handle'] = 0
        r['acct_flags'] = user_account_flags
        r['max_size'] = 1000

        result = dcerpc.samr_EnumDomainUsers(self.pipe, r)

        return result


def Connect(pipe, system_name = None, access_mask = 0x02000000):
    """Connect to the SAMR pipe."""

    r = {}
    r['system_name'] = system_name
    r['access_mask'] = access_mask

    result = dcerpc.samr_Connect2(pipe, r)

    return ConnectHandle(pipe, result['connect_handle'])
