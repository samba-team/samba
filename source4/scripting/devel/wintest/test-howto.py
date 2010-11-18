#!/usr/bin/env python

'''automated testing of the steps of the Samba4 HOWTO'''

import sys, os
import optparse
import wintest

vars = {}

def check_prerequesites(t):
    t.info("Checking prerequesites")
    t.setvar('HOSTNAME', t.cmd_output("hostname -s").strip())
    if os.getuid() != 0:
        raise Exception("You must run this script as root")
    t.cmd_contains("grep 127.0.0.1 /etc/resolv.conf", ["nameserver 127.0.0.1"])


def build_s4(t):
    '''build samba4'''
    t.info('Building s4')
    t.chdir('${SOURCETREE}/source4')
    t.putenv('CC', 'ccache gcc')
    t.run_cmd('make reconfigure || ./configure --enable-auto-reconfigure --enable-developer --prefix=${PREFIX} -C')
    t.run_cmd('make -j')
    t.run_cmd('rm -rf ${PREFIX}')
    t.run_cmd('make -j install')

def provision_s4(t):
    '''provision s4 as a DC'''
    t.info('Provisioning s4')
    t.chdir('${PREFIX}')
    t.run_cmd("rm -rf etc private")
    t.run_cmd('sbin/provision --realm=${LCREALM} --domain=${DOMAIN} --adminpass=${PASSWORD1} --server-role="domain controller" --function-level=2008 -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool newuser testallowed ${PASSWORD1}')
    t.run_cmd('bin/samba-tool newuser testdenied ${PASSWORD1}')
    t.run_cmd('bin/samba-tool group addmembers "Allowed RODC Password Replication Group" testallowed')

def start_s4(t, interfaces=None):
    t.info('Starting Samba4')
    t.chdir("${PREFIX}")
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.run_cmd(['sbin/samba',
             '--option', 'panic action=gnome-terminal -e "gdb --pid %PID%"',
             '--option', 'interfaces=%s' % interfaces])
    t.port_wait("localhost", 445)

def test_smbclient(t):
    t.info('Testing smbclient')
    t.chdir('${PREFIX}')
    t.cmd_contains("bin/smbclient --version", ["Version 4.0"])
    t.retry_cmd('bin/smbclient -L localhost -U%', ["netlogon", "sysvol", "IPC Service"])
    child = t.pexpect_spawn('bin/smbclient //localhost/netlogon -Uadministrator%${PASSWORD1}')
    child.expect("smb:")
    child.sendline("dir")
    child.expect("blocks available")
    child.sendline("mkdir testdir")
    child.expect("smb:")
    child.sendline("cd testdir")
    child.expect('testdir')
    child.sendline("cd ..")
    child.sendline("rmdir testdir")

def create_shares(t):
    t.info("Adding test shares")
    t.chdir('${PREFIX}')
    f = open("etc/smb.conf", mode='a')
    f.write(t.substitute('''
[test]
       path = ${PREFIX}/test
       read only = no
[profiles]
       path = ${PREFIX}/var/profiles
       read only = no
    '''))
    f.close()
    t.run_cmd("mkdir -p test")
    t.run_cmd("mkdir -p var/profiles")


def restart_bind(t):
    t.info("Restarting bind9")
    t.putenv('KEYTAB_FILE', '${PREFIX}/private/dns.keytab')
    t.putenv('KRB5_KTNAME', '${PREFIX}/private/dns.keytab')
    t.run_cmd('killall -9 -q named', checkfail=False)
    t.port_wait("localhost", 53, wait_for_fail=True)
    t.run_cmd("${BIND9}")
    t.port_wait("localhost", 53)
    t.run_cmd("${RNDC} flush")
    t.run_cmd("${RNDC} freeze")
    t.run_cmd("${RNDC} thaw")

def test_dns(t):
    t.info("Testing DNS")
    t.cmd_contains("host -t SRV _ldap._tcp.${LCREALM}.",
                 ['_ldap._tcp.${LCREALM} has SRV record 0 100 389 ${HOSTNAME}.${LCREALM}'])
    t.cmd_contains("host -t SRV  _kerberos._udp.${LCREALM}.",
                 ['_kerberos._udp.${LCREALM} has SRV record 0 100 88 ${HOSTNAME}.${LCREALM}'])
    t.cmd_contains("host -t A ${HOSTNAME}.${LCREALM}",
                 ['${HOSTNAME}.${LCREALM} has address'])

def test_kerberos(t):
    t.info("Testing kerberos")
    t.run_cmd("kdestroy")
    t.kinit("administrator@${REALM}", "${PASSWORD1}")
    t.cmd_contains("klist -e", ["Ticket cache", "Default principal", "Valid starting"])


def test_dyndns(t):
    t.chdir('${PREFIX}')
    t.run_cmd("sbin/samba_dnsupdate --fail-immediately")
    t.run_cmd("${RNDC} flush")


def run_winjoin(t, vm):
    t.setwinvars(vm)

    t.info("Joining a windows box to the domain")
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.ping_wait("${WIN_HOSTNAME}")
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "${WIN_USER}", "${WIN_PASS}", set_time=True)
    child.sendline("netdom join ${WIN_HOSTNAME} /Domain:${LCREALM} /PasswordD:${PASSWORD1} /UserD:administrator")
    child.expect("The command completed successfully")
    child.sendline("shutdown /r -t 0")
    t.port_wait("${WIN_HOSTNAME}", 23, wait_for_fail=True)
    t.port_wait("${WIN_HOSTNAME}", 23)


def test_winjoin(t, vm):
    t.setwinvars(vm)
    t.info("Checking the windows join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WIN_HOSTNAME}", 445)
    t.retry_cmd('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WIN_HOSTNAME}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -k no -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -k yes -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "${DOMAIN}\\administrator", "${PASSWORD1}")
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")
    t.vm_poweroff("${WIN_VM}")


def run_dcpromo(t, vm):
    '''run a dcpromo on windows'''
    t.setwinvars(vm)
    
    t.info("Joining a windows VM ${WIN_VM} to the domain as a DC using dcpromo")
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.ping_wait("${WIN_HOSTNAME}")
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "administrator", "${WIN_PASS}")
    child.sendline("copy /Y con answers.txt")
    child.sendline('''
[DCInstall]
ReplicaOrNewDomain=Replica
ReplicaDomainDNSName=${LCREALM}
SiteName=Default-First-Site-Name
InstallDNS=No
ConfirmGc=Yes
CreateDNSDelegation=No
UserDomain=${LCREALM}
UserName=${LCREALM}\\administrator
Password=${PASSWORD1}
DatabasePath="C:\Windows\NTDS"
LogPath="C:\Windows\NTDS"
SYSVOLPath="C:\Windows\SYSVOL"
SafeModeAdminPassword=${PASSWORD1}
RebootOnCompletion=No

''')
    child.expect("copied.")
    child.sendline("dcpromo /answer:answers.txt")
    i = child.expect(["You must restart this computer", "failed"], timeout=120)
    if i != 0:
        raise Exception("dcpromo failed")
    child.sendline("shutdown -r -t 0")
    t.port_wait("${WIN_HOSTNAME}", 23, wait_for_fail=True)
    t.port_wait("${WIN_HOSTNAME}", 23)


def test_dcpromo(t, vm):
    t.setwinvars(vm)
    t.info("Checking the dcpromo join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WIN_HOSTNAME}", 445)
    t.retry_cmd('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WIN_HOSTNAME}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WIN_HOSTNAME}", 23)

    t.cmd_contains("bin/samba-tool drs kcc ${HOSTNAME} -Uadministrator@${LCREALM}%${PASSWORD1}", ['Consistency check', 'successful'])
    t.cmd_contains("bin/samba-tool drs kcc ${WIN_HOSTNAME} -Uadministrator@${LCREALM}%${PASSWORD1}", ['Consistency check', 'successful'])

    t.kinit("administrator@${REALM}", "${PASSWORD1}")
    for nc in [ '${BASEDN}', 'CN=Configuration,${BASEDN}', 'CN=Schema,CN=Configuration,${BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WIN_HOSTNAME} %s -k yes" % nc, ["was successful"])
        t.cmd_contains("bin/samba-tool drs replicate ${WIN_HOSTNAME} ${HOSTNAME} %s -k yes" % nc, ["was successful"])

    t.cmd_contains("bin/samba-tool drs showrepl ${HOSTNAME} -k yes",
                 [ "INBOUND NEIGHBORS",
                   "${BASEDN}",
                   "Last attempt", "was successful",
                   "CN=Schema,CN=Configuration,${BASEDN}",
                   "Last attempt", "was successful",
                   "OUTBOUND NEIGHBORS",
                   "${BASEDN}",
                   "Last success",
                   "CN=Configuration,${BASEDN}",
                   "Last success"],
                 ordered=True)

    t.cmd_contains("bin/samba-tool drs showrepl ${WIN_HOSTNAME} -k yes",
                 [ "INBOUND NEIGHBORS",
                   "${BASEDN}",
                   "Last attempt", "was successful",
                   "CN=Schema,CN=Configuration,${BASEDN}",
                   "Last attempt", "was successful",
                   "OUTBOUND NEIGHBORS",
                   "${BASEDN}",
                   "Last success",
                   "CN=Schema,CN=Configuration,${BASEDN}",
                   "Last success" ],
                 ordered=True)

    child = t.open_telnet("${WIN_HOSTNAME}", "${DOMAIN}\\administrator", "${PASSWORD1}", set_time=True)
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")

    t.run_net_time(child)

    t.info("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${BASEDN}")
    child.expect("was successful")

    t.info("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    t.info("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    while True:
        i = child.expect(["The command completed successfully",
                          "The directory service was unable to allocate a relative identifier"])
        if i == 0:
            break
        time.sleep(2)

    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['Sharename', 'IPC'])

    t.info("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WIN_VM}")


def run_dcpromo_rodc(t, vm):
    t.setwinvars(vm)
    t.info("Joining a w2k8 box to the domain as a RODC")
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.ping_wait("${WIN_HOSTNAME}")
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "administrator", "${WIN_PASS}")
    child.sendline("copy /Y con answers.txt")
    child.sendline('''
[DCInstall]
ReplicaOrNewDomain=ReadOnlyReplica
ReplicaDomainDNSName=${LCREALM}
PasswordReplicationDenied="BUILTIN\Administrators"
PasswordReplicationDenied="BUILTIN\Server Operators"
PasswordReplicationDenied="BUILTIN\Backup Operators"
PasswordReplicationDenied="BUILTIN\Account Operators"
PasswordReplicationDenied="${DOMAIN}\Denied RODC Password Replication Group"
PasswordReplicationAllowed="${DOMAIN}\Allowed RODC Password Replication Group"
DelegatedAdmin="${DOMAIN}\\Administrator"
SiteName=Default-First-Site-Name
InstallDNS=No
ConfirmGc=Yes
CreateDNSDelegation=No
UserDomain=${LCREALM}
UserName=${LCREALM}\\administrator
Password=${PASSWORD1}
DatabasePath="C:\Windows\NTDS"
LogPath="C:\Windows\NTDS"
SYSVOLPath="C:\Windows\SYSVOL"
SafeModeAdminPassword=${PASSWORD1}
RebootOnCompletion=No

''')
    child.expect("copied.")
    child.sendline("dcpromo /answer:answers.txt")
    i = child.expect(["You must restart this computer", "failed"], timeout=120)
    if i != 0:
        raise Exception("dcpromo failed")
    child.sendline("shutdown -r -t 0")
    t.port_wait("${WIN_HOSTNAME}", 23, wait_for_fail=True)
    t.port_wait("${WIN_HOSTNAME}", 23)



def test_dcpromo_rodc(t, vm):
    t.setwinvars(vm)
    t.info("Checking the w2k8 RODC join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WIN_HOSTNAME}", 445)
    t.retry_cmd('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WIN_HOSTNAME}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WIN_HOSTNAME}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "${DOMAIN}\\administrator", "${PASSWORD1}", set_time=True)
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")

    t.info("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${BASEDN}")
    child.expect("was successful")

    t.info("Checking if new users are available on windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2}", ['LOGON_FAILURE'])
    t.vm_poweroff("${WIN_VM}")


def join_as_dc(t, vm):
    t.setwinvars(vm)
    t.info("Joining ${WIN_VM} as a second DC using samba-tool join DC")
    t.chdir('${PREFIX}')
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.run_cmd('${RNDC} flush')
    t.run_cmd("rm -rf etc private")
    t.open_telnet("${WIN_HOSTNAME}", "${WIN_DOMAIN}\\administrator", "${WIN_PASS}", set_time=True)
    t.retry_cmd("bin/samba-tool drs showrepl ${WIN_HOSTNAME} -Uadministrator%${WIN_PASS}", ['INBOUND NEIGHBORS'] )
    t.run_cmd('bin/samba-tool join ${WIN_REALM} DC -Uadministrator%${WIN_PASS} -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool drs kcc ${WIN_HOSTNAME} -Uadministrator@${WIN_REALM}%${WIN_PASS}')


def test_join_as_dc(t, vm):
    t.setwinvars(vm)
    t.info("Checking the DC join is OK")
    t.chdir('${PREFIX}')
    t.retry_cmd('bin/smbclient -L ${HOSTNAME}.${WIN_REALM} -Uadministrator@${WIN_REALM}%${WIN_PASS}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${HOSTNAME}.${WIN_REALM}.", ['has address'])
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "${WIN_DOMAIN}\\administrator", "${WIN_PASS}", set_time=True)

    t.info("Forcing kcc runs, and replication")
    t.run_cmd('bin/samba-tool drs kcc ${WIN_HOSTNAME} -Uadministrator@${WIN_REALM}%${WIN_PASS}')
    t.run_cmd('bin/samba-tool drs kcc ${HOSTNAME} -Uadministrator@${WIN_REALM}%${WIN_PASS}')

    t.kinit("administrator@${WIN_REALM}", "${WIN_PASS}")
    for nc in [ '${WIN_BASEDN}', 'CN=Configuration,${WIN_BASEDN}', 'CN=Schema,CN=Configuration,${WIN_BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WIN_HOSTNAME} %s -k yes" % nc, ["was successful"])
        t.cmd_contains("bin/samba-tool drs replicate ${WIN_HOSTNAME} ${HOSTNAME} %s -k yes" % nc, ["was successful"])

    child.sendline("net use t: \\\\${HOSTNAME}.${WIN_REALM}\\test")
    child.expect("The command completed successfully")

    t.info("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${WIN_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${WIN_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${WIN_BASEDN}")
    child.expect("was successful")

    t.info("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    t.info("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    t.info("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WIN_REALM}%${WIN_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WIN_VM}")


def join_as_rodc(t, vm):
    t.setwinvars(vm)
    t.info("Joining ${WIN_VM} as a RODC using samba-tool join DC")
    t.chdir('${PREFIX}')
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.run_cmd('${RNDC} flush')
    t.run_cmd("rm -rf etc private")
    t.open_telnet("${WIN_HOSTNAME}", "${WIN_DOMAIN}\\administrator", "${WIN_PASS}", set_time=True)
    t.retry_cmd("bin/samba-tool drs showrepl ${WIN_HOSTNAME} -Uadministrator%${WIN_PASS}", ['INBOUND NEIGHBORS'] )
    t.run_cmd('bin/samba-tool join ${WIN_REALM} RODC -Uadministrator%${WIN_PASS} -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool drs kcc ${WIN_HOSTNAME} -Uadministrator@${WIN_REALM}%${WIN_PASS}')


def test_join_as_rodc(t, vm):
    t.setwinvars(vm)
    t.info("Checking the RODC join is OK")
    t.chdir('${PREFIX}')
    t.retry_cmd('bin/smbclient -L ${HOSTNAME}.${WIN_REALM} -Uadministrator@${WIN_REALM}%${WIN_PASS}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${HOSTNAME}.${WIN_REALM}.", ['has address'])
    t.port_wait("${WIN_HOSTNAME}", 23)
    child = t.open_telnet("${WIN_HOSTNAME}", "${WIN_DOMAIN}\\administrator", "${WIN_PASS}", set_time=True)

    t.info("Forcing kcc runs, and replication")
    t.run_cmd('bin/samba-tool drs kcc ${WIN_HOSTNAME} -Uadministrator@${WIN_REALM}%${WIN_PASS}')

    t.kinit("administrator@${WIN_REALM}", "${WIN_PASS}")
    for nc in [ '${WIN_BASEDN}', 'CN=Configuration,${WIN_BASEDN}', 'CN=Schema,CN=Configuration,${WIN_BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WIN_HOSTNAME} %s -k yes" % nc, ["was successful"])

    child.sendline("net use t: \\\\${HOSTNAME}.${WIN_REALM}\\test")
    child.expect("The command completed successfully")

    t.info("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${WIN_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${WIN_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${WIN_BASEDN}")
    child.expect("was successful")

    t.info("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    t.info("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    t.info("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WIN_REALM}%${WIN_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WIN_HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WIN_VM}")


def test_howto(t):
    '''test the Samba4 howto'''

    check_prerequesites(t)

    if not t.skip("build"):
        build_s4(t)
    if not t.skip("provision"):
        provision_s4(t)

    if not t.skip("create-shares"):
        create_shares(t)

    if not t.skip("starts4"):
        start_s4(t, interfaces='${INTERFACES}')
    if not t.skip("smbclient"):
        test_smbclient(t)
    if not t.skip("startbind"):
        restart_bind(t)
    if not t.skip("dns"):
        test_dns(t)
    if not t.skip("kerberos"):
        test_kerberos(t)
    if not t.skip("dyndns"):
        test_dyndns(t)
    
    if not t.skip("windows7"):
        run_winjoin(t, "WINDOWS7")
        test_winjoin(t, "WINDOWS7")

    if not t.skip("winxp"):
        run_winjoin(t, "WINXP")
        test_winjoin(t, "WINXP")
    
    if not t.skip("dcpromo_rodc"):
        t.info("Testing w2k8r2 RODC dcpromo")
        run_dcpromo_rodc(t, "WINDOWS_DC2")
        test_dcpromo_rodc(t, "WINDOWS_DC2")

    if not t.skip("dcpromo_w2k8r2"):
        t.info("Testing w2k8r2 dcpromo")
        run_dcpromo(t, "WINDOWS_DC1")
        test_dcpromo(t, "WINDOWS_DC1")

    if not t.skip("dcpromo_w2k8"):
        t.info("Testing w2k8 dcpromo")
        run_dcpromo(t, "WINDOWS_DC5")
        test_dcpromo(t, "WINDOWS_DC5")
    
    if not t.skip("join_w2k8r2"):
        join_as_dc(t, "WINDOWS_DC3")
        create_shares(t)
        start_s4(t, interfaces='${INTERFACES}')
        test_dyndns(t)
        test_join_as_dc(t, "WINDOWS_DC3")

    if not t.skip("join_rodc"):
        join_as_rodc(t, "WINDOWS_DC3")
        create_shares(t)
        start_s4(t, interfaces='${INTERFACES}')
        test_dyndns(t)
        test_join_as_rodc(t, "WINDOWS_DC3")
    
    if not t.skip("join_w2k3"):
        join_as_dc(t, "WINDOWS_DC4")
        create_shares(t)
        start_s4(t, interfaces='${INTERFACES}')
        test_dyndns(t)
        test_join_as_dc(t, "WINDOWS_DC4")

    t.info("Howto test: All OK")


if __name__ == '__main__':
    parser = optparse.OptionParser("test-howto.py")
    parser.add_option("--conf", type='string', default='', help='config file')
    parser.add_option("--skip", type='string', default='', help='list of steps to skip (comma separated)')
    parser.add_option("--list", action='store_true', default=False, help='list the available steps')
    parser.add_option("--rebase", action='store_true', default=False, help='do a git pull --rebase')
    parser.add_option("--clean", action='store_true', default=False, help='clean the tree')

    opts, args = parser.parse_args()

    if not opts.conf:
        t.info("Please specify a config file with --conf")
        sys.exit(1)

    t = wintest.wintest()
    t.load_config(opts.conf)
    t.set_skip(opts.skip)
    if opts.list:
        t.list_steps_mode()

    if opts.rebase:
        t.info('rebasing')
        t.chdir('${SOURCETREE}')
        t.run_cmd('git pull --rebase')

    if opts.clean:
        t.info('rebasing')
        t.chdir('${SOURCETREE}/source4')
        t.run_cmd('rm -rf bin')

    test_howto(t)
