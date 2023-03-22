# Test SDDL strings on Windows
#
# Copyright (c) 2023 Catalyst IT
#
# GPLv3+.
#
# This uses the Python ctypes module to access the sddl.h functions.

from ctypes import WINFUNCTYPE
from ctypes import create_string_buffer, byref, windll, c_void_p, pointer
from ctypes.wintypes import LPCSTR, PULONG, LPVOID, DWORD, BOOL, ULONG

f = windll.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorA
#f.restype = BOOL
f.argtypes = (LPCSTR, DWORD, LPVOID, PULONG)

err = windll.kernel32.GetLastError
set_err = windll.kernel32.SetLastError

def check_sddl(sddl):
    out_size = PULONG()
    out_bytes = LPVOID()
    _sddl = sddl.encode('utf8')
    #print(_sddl, DWORD(1), out_bytes, out_size)
    ok = f(_sddl, 1, out_bytes, out_size)
    if not ok:
        #breakpoint()
        e = err()
        if e != 87:
            print(e)
        set_err(0)
    return ok


def check_sddl_powershell(sddl):
    import subprocess
    p = subprocess.run(['powershell.exe',
                        #'-windowstyle', 'hidden',
                        #'-executionpolicy', 'bypass',
                        #'-noninteractive',
                         'ConvertFrom-SddlString',
                         '-Sddl',
                         '"' + sddl.replace(';', '`;') + '"',
                        '-type', 'ActiveDirectoryRights',
                        ],
                       capture_output=True
                       )
    print()
    stderr = p.stderr.decode()
    stdout = p.stdout.decode()
    if 'Exception' in stderr:
        print(sddl)
        if 'security descriptor object is invalid'  not in stderr:
            print(stdout)
            print(stderr)
            return None # probably ok

        return False

    #print(stdout)
    return True


def main():
    cases = [
        "awoivhewo42u",
        "D:(A;OICI;GA;;;WD)",
        "",
        "O:BAG:BAD:",
        "O:BAG:DAD:",
        "O:BAG:baD:",
        "O:baG:BAD:",
        "O:BAG:BUS:",
        "O:BAD:BAG:",
        "O:BAG:MUD:",
        "G:BAO:BUS:",
        "O:BAG:BUS:",
        "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)",

        "D:(A;;GA;;;SY)",

        "D:(A;;GA;;;RS)",

        "D:(A;;RP;;;WD)",
        "D:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)",
        "D:(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)",
        "D:(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)",
        "D:(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)",
        "D:(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)",
        "D:(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)",
        "D:(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)",
        "D:(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)",
        "D:(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)",
        "D:(A;CI;LC;;;RU)",
        "D:(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)",
        "D:(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(A;;RPRC;;;RU)",
        "D:(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)",
        "D:(A;;LCRPLORC;;;ED)",
        "D:(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)",
        "D:(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)",
        "D:(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)",
        "D:(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)",
        "S:(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)",
        "S:(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)",
        "S:(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)",
        "S:(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)",
        "S:(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)",
        "S:(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)",
        "S:(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)",
        "S:(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)",
        "S:(AU;SA;CR;;;BA)",
        "S:(AU;SA;CR;;;DU)",
        "S:(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)",
        "S:(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)",
        "D:(A;;RPLCLORC;;;DA)",
        "S:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "S:(A;;RPLCLORC;;;AU)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "S:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)",
        "S:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "S:(A;;RPCRLCLORCSDDT;;;CO)",
        "S:(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)",
        "S:(A;;RPLCLORC;;;AU)",
        "S:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)",
        "S:(A;;CCDC;;;PS)",
        "S:(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)",
        "S:(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)",
        "S:(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)",
        "S:(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)",
        "S:(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)",
        "S:(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)",
        "D:(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)",
        "D:(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)",
        "D:(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)",
        "D:(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)",
        "D:(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)",
        "D:(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)",
        "D:(A;;RPLCLORC;;;PS)",
        "D:(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)",
        "D:(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)",
        "D:(A;;RPLCLORC;;;PS)",
        "D:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)",
        "D:(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)",
        "D:(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)",
        "D:(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)",
        "D:(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)",
        "D:(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)",
        "D:(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)",
        "D:(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)",
        "D:(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)",
        "D:(A;;RC;;;AU)",
        "D:(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)",
        "D:(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)",
        "D:(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)",
        "D:(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)",
        "D:(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)",
        "D:(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)",
        "D:(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)",
        "D:(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)",
        "D:(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;LCRPLORC;;;ED)",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)",
        "D:(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)",
        "D:(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)",
        "D:(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)",
        "D:(A;;RPLCLORC;;;AU)",
        "D:(A;;LCRPLORC;;;ED)",
        "D:(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",

        "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",

        "D:S:",
        "D:PS:",

        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)",
        "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)",
        "D:(A;;RPLCLORC;;;AU)",

        "S:D:P",
    ]
    good_cases = []
    bad_cases = []
    uncertain_cases = []
    print(len(cases))
    print(len(set(cases)))
    for case in set(cases):
        res = check_sddl_powershell(case)
        #res = check_sddl(case)
        if res:
            print(f"good: {case}")
            good_cases.append(case)
        elif res is None:
            print(f"unknown: {case}")
            uncertain_cases.append(case)
        else:
            bad_cases.append(case)

    print(f"{len(bad_cases)} bad")
    for c in bad_cases:
        print(f"BAD: {c}")

    print(f"{len(uncertain_cases)} uncertain")
    for c in uncertain_cases:
        print(f"MAYBE: {c}")

    print(f"{len(good_cases)} good")
    for c in good_cases:
        print(f"GOOD: {c}")


main()
