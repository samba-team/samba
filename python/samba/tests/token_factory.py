# Unix SMB/CIFS implementation.
# Copyright © Catalyst IT 2023
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
"""An API for creating arbitrary security tokens."""


from samba.dcerpc import security


CLAIM_VAL_TYPES = {
    int: 0x0001,
    'uint': 0x0002,
    str: 0x0003,
    security.dom_sid: 0x0005,
    bool: 0x0006,
    bytes: 0x0010
}


def list_to_claim(k, v, case_sensitive=False):
    if isinstance(v, security.CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1):
        # make the name match
        v.name = k
        return v
    if isinstance(v, (str, int)):
        v = [v]
    if not isinstance(v, list):
        raise TypeError(f"expected list of claim values for '{k}', "
                        f"not {v!r} of type {type(v)}")

    c = security.CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1()

    if len(v) != 0:
        t = type(v[0])
        c.value_type = CLAIM_VAL_TYPES[t]
        for val in v[1:]:
            if type(val) is not t:
                raise TypeError(f"claim values for '{k}' "
                                "should all be the same type")
    else:
        # pick an arbitrary type
        c.value_type = CLAIM_VAL_TYPES['uint']
    c.name = k
    c.values = v
    c.value_count = len(v)
    if case_sensitive:
        c.flags |= security.CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE

    # The claims made here will not have the
    # CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED flag set, which makes
    # them like resource attribute claims rather than real wire
    # claims. It shouldn't matter much, as they will just be sorted
    # and checked as if they were resource attribute claims.
    return c


def _normalise_claims(args):
    if isinstance(args, security.CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1):
        return [args]

    if args is None or len(args) == 0:
        return []

    if isinstance(args, list):
        for x in args:
            if not isinstance(x, security.CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1):
                raise TypeError(f"list should be of claims, not '{type(x)}'")
        return args

    claims_out = []

    if isinstance(args, dict):
        # the key is the name and the value is a list of claim values
        for k, v in args.items():
            c = list_to_claim(k, v)
            claims_out.append(c)

    return claims_out


def str_to_sid(s):
    lut = {
        # These are a subset of two letter aliases that don't need a
        # domain SID or other magic. (c.f. sid_strings test).
        'AA': security.SID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPS,  # S-1-5-32-579
        'AC': security.SID_SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE,  # S-1-15-2-1
        'AN': security.SID_NT_ANONYMOUS,                          # S-1-5-7
        'AO': security.SID_BUILTIN_ACCOUNT_OPERATORS,             # S-1-5-32-548
        'AS': security.SID_AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY,  # S-1-18-1
        'AU': security.SID_NT_AUTHENTICATED_USERS,                # S-1-5-11
        'BA': security.SID_BUILTIN_ADMINISTRATORS,                # S-1-5-32-544
        'BG': security.SID_BUILTIN_GUESTS,                        # S-1-5-32-546
        'BO': security.SID_BUILTIN_BACKUP_OPERATORS,              # S-1-5-32-551
        'BU': security.SID_BUILTIN_USERS,                         # S-1-5-32-545
        'CD': security.SID_BUILTIN_CERT_SERV_DCOM_ACCESS,         # S-1-5-32-574
        'CG': security.SID_CREATOR_GROUP,                         # S-1-3-1
        'CO': security.SID_CREATOR_OWNER,                         # S-1-3-0
        'CY': security.SID_BUILTIN_CRYPTO_OPERATORS,              # S-1-5-32-569
        'ED': security.SID_NT_ENTERPRISE_DCS,                     # S-1-5-9
        'ER': security.SID_BUILTIN_EVENT_LOG_READERS,             # S-1-5-32-573
        'ES': security.SID_BUILTIN_RDS_ENDPOINT_SERVERS,          # S-1-5-32-576
        'HA': security.SID_BUILTIN_HYPER_V_ADMINS,                # S-1-5-32-578
        'HI': security.SID_SECURITY_MANDATORY_HIGH,               # S-1-16-12288
        'IS': security.SID_BUILTIN_IUSERS,                        # S-1-5-32-568
        'IU': security.SID_NT_INTERACTIVE,                        # S-1-5-4
        'LS': security.SID_NT_LOCAL_SERVICE,                      # S-1-5-19
        'LU': security.SID_BUILTIN_PERFLOG_USERS,                 # S-1-5-32-559
        'LW': security.SID_SECURITY_MANDATORY_LOW,                # S-1-16-4096
        'ME': security.SID_SECURITY_MANDATORY_MEDIUM,             # S-1-16-8192
        'MP': security.SID_SECURITY_MANDATORY_MEDIUM_PLUS,        # S-1-16-8448
        'MS': security.SID_BUILTIN_RDS_MANAGEMENT_SERVERS,        # S-1-5-32-577
        'MU': security.SID_BUILTIN_PERFMON_USERS,                 # S-1-5-32-558
        'NO': security.SID_BUILTIN_NETWORK_CONF_OPERATORS,        # S-1-5-32-556
        'NS': security.SID_NT_NETWORK_SERVICE,                    # S-1-5-20
        'NU': security.SID_NT_NETWORK,                            # S-1-5-2
        'OW': security.SID_OWNER_RIGHTS,                          # S-1-3-4
        'PO': security.SID_BUILTIN_PRINT_OPERATORS,               # S-1-5-32-550
        'PS': security.SID_NT_SELF,                               # S-1-5-10
        'PU': security.SID_BUILTIN_POWER_USERS,                   # S-1-5-32-547
        'RA': security.SID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS,     # S-1-5-32-575
        'RC': security.SID_NT_RESTRICTED,                         # S-1-5-12
        'RD': security.SID_BUILTIN_REMOTE_DESKTOP_USERS,          # S-1-5-32-555
        'RE': security.SID_BUILTIN_REPLICATOR,                    # S-1-5-32-552
        'RM': security.SID_BUILTIN_REMOTE_MANAGEMENT_USERS,       # S-1-5-32-580
        'RU': security.SID_BUILTIN_PREW2K,                        # S-1-5-32-554
        'SI': security.SID_SECURITY_MANDATORY_SYSTEM,             # S-1-16-16384
        'SO': security.SID_BUILTIN_SERVER_OPERATORS,              # S-1-5-32-549
        'SS': security.SID_SERVICE_ASSERTED_IDENTITY,             # S-1-18-2
        'SU': security.SID_NT_SERVICE,                            # S-1-5-6
        'SY': security.SID_NT_SYSTEM,                             # S-1-5-18
        'WD': security.SID_WORLD,                                 # S-1-1-0
        'WR': security.SID_SECURITY_RESTRICTED_CODE,              # S-1-5-33
    }
    if s in lut:
        s = lut[s]
    return security.dom_sid(s)


def _normalise_sids(args):
    if isinstance(args, security.dom_sid):
        return [args]
    if isinstance(args, str):
        return [str_to_sid(args)]

    if not isinstance(args, list):
        raise TypeError("expected a SID, sid string, or list of SIDs, "
                        f"not'{type(args)}'")

    sids_out = []
    for s in args:
        if isinstance(s, str):
            s = str_to_sid(s)
        elif not isinstance(s, security.dom_sid):
            raise TypeError(f"expected a SID, not'{type(s)}'")
        sids_out.append(s)

    return sids_out


def _normalise_mask(mask, mask_type):
    if isinstance(mask, int):
        return mask

    if not isinstance(mask, list):
        raise TypeError("expected int mask or list of flags")

    if mask_type == 'privileges':
        prefix = 'SEC_PRIV_'
        tail = '_BIT'
    elif mask_type == 'rights':
        prefix = 'LSA_POLICY_MODE_'
        tail = ''
    else:
        raise ValueError(f"unknown mask_type value: {mask_type}")

    mask_out = 0

    for x in mask:
        if isinstance(x, str) and x.startswith(prefix):
            if not x.endswith(tail):
                # we don't want security.SEC_PRIV_SHUTDOWN (19),
                # we want security.SEC_PRIV_SHUTDOWN_BIT (1 << 20)
                # but you can write "SEC_PRIV_SHUTDOWN"
                x += tail
            x = getattr(security, x)
        mask_out |= x

    return mask_out


def token(sids=None, **kwargs):
    """Return a security token with the specified attributes.

    The security.token API is annoying and fragile; here we wrap it in
    something nicer.

    In general the arguments can either be objects of the correct
    type, or Python strings or structures that clearly convert to that
    type. For example, there two are equivalent:

    >>> t = token([security.dom_sid("S-1-2")])
    >>> t = token(["S-1-2"])

    To add claims and device SIDs you do something like this:

    >>> t = token(["AA", "WD"],
                  device_sids=["WD"],
                  user_claims={"Title": ["PM"],
                               "ClearanceLevel": [1]}
    """

    claims_kws = ['device_claims',
                  'local_claims',
                  'user_claims']

    sid_kws = ['sids', 'device_sids']

    mask_kws = ['privileges',
                'rights']

    if sids is not None:
        kwargs['sids'] = sids

    norm_args = {}

    for k, v in kwargs.items():
        if k in claims_kws:
            norm_args[k] = _normalise_claims(v)
        elif k in mask_kws:
            norm_args[k] = _normalise_mask(v, k)
        elif k in sid_kws:
            norm_args[k] = _normalise_sids(v)
        else:
            raise TypeError(f"{k} is an invalid keyword argument")

    t = security.token(evaluate_claims=security.CLAIMS_EVALUATION_ALWAYS)

    for k, v in norm_args.items():
        setattr(t, k, v)
        if isinstance(v, list):
            setattr(t, 'num_' + k, len(v))

    return t
