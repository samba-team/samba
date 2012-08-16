connect
open x RC 0700
sys_acl_get_file . 0
sys_acl_get_file . 1
get_nt_acl .
set_nt_acl . G:DAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)
get_nt_acl .
sys_acl_get_file . 0
sys_acl_get_file . 1
get_nt_acl x
sys_acl_get_file x 0
set_nt_acl x G:DAD:P(A;OICI;0x001f01ff;;;BA)(A;OICI;0x001200a9;;;SO)(A;OICI;0x001f01ff;;;SY)(A;OICI;0x001200a9;;;AU)
get_nt_acl x
sys_acl_get_file x 0

