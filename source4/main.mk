mkinclude dynconfig.mk
heimdalsrcdir := heimdal
mkinclude heimdal_build/config.mk
mkinclude config.mk
dsdbsrcdir := dsdb
mkinclude dsdb/config.mk
smbdsrcdir := smbd
mkinclude smbd/config.mk
clustersrcdir := cluster
mkinclude cluster/config.mk
mkinclude smbd/process_model.mk
libnetsrcdir := libnet
mkinclude libnet/config.mk
authsrcdir := auth
mkinclude auth/config.mk
nsswitchsrcdir = nsswitch
mkinclude nsswitch/config.mk
mkinclude lib/basic.mk
paramsrcdir := param
mkinclude param/config.mk
smb_serversrcdir := smb_server
mkinclude smb_server/config.mk
rpc_serversrcdir := rpc_server
mkinclude rpc_server/config.mk
ldap_serversrcdir := ldap_server
mkinclude ldap_server/config.mk
web_serversrcdir := web_server
mkinclude web_server/config.mk
winbindsrcdir := winbind
mkinclude winbind/config.mk
nbt_serversrcdir := nbt_server
mkinclude nbt_server/config.mk
wrepl_serversrcdir := wrepl_server
mkinclude wrepl_server/config.mk
cldap_serversrcdir := cldap_server
mkinclude cldap_server/config.mk
utilssrcdir := utils
mkinclude utils/net/config.mk
mkinclude utils/config.mk
ntvfssrcdir := ntvfs
mkinclude ntvfs/config.mk
ntptrsrcdir := ntptr
mkinclude ntptr/config.mk
torturesrcdir := torture
mkinclude torture/config.mk
librpcsrcdir := librpc
mkinclude librpc/config.mk
clientsrcdir := client
mkinclude client/config.mk
libclisrcdir := libcli
mkinclude libcli/config.mk
mkinclude scripting/ejs/config.mk
pyscriptsrcdir := scripting/python
mkinclude scripting/python/config.mk
kdcsrcdir := kdc
mkinclude kdc/config.mk
