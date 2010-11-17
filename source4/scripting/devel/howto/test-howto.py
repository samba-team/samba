#!/usr/bin/env python

'''automated testing of the steps of the Samba4 HOWTO'''

import sys, os
import optparse
import wintest

vars = {}

parser = optparse.OptionParser("samba_dnsupdate")
parser.add_option("--conf", type='string', default='', help='config file')


def check_prerequesites(t):
    print("Checking prerequesites")
    t.setvar('HOSTNAME', t.cmd_output("hostname -s").strip())
    if os.getuid() != 0:
        raise Exception("You must run this script as root")
    t.cmd_contains("grep 127.0.0.1 /etc/resolv.conf", ["nameserver 127.0.0.1"])


def build_s4(t):
    '''build samba4'''
    print('Building s4')
    t.chdir('${SOURCETREE}/source4')
    t.putenv('CC', 'ccache gcc')
    t.run_cmd('make reconfigure || ./configure --enable-auto-reconfigure --enable-developer --prefix=${PREFIX} -C')
    t.run_cmd('make -j')
    t.run_cmd('rm -rf ${PREFIX}')
    t.run_cmd('make -j install')

def provision_s4(t):
    '''provision s4 as a DC'''
    print('Provisioning s4')
    t.chdir('${PREFIX}')
    t.run_cmd("rm -rf etc private")
    t.run_cmd('sbin/provision --realm=${LCREALM} --domain=${DOMAIN} --adminpass=${PASSWORD1} --server-role="domain controller" --function-level=2008 -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool newuser testallowed ${PASSWORD1}')
    t.run_cmd('bin/samba-tool newuser testdenied ${PASSWORD1}')
    t.run_cmd('bin/samba-tool group addmembers "Allowed RODC Password Replication Group" testallowed')

def start_s4(t, interfaces=None):
    print('Starting Samba4')
    t.chdir("${PREFIX}")
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.run_cmd(['sbin/samba',
             '--option', 'panic action=gnome-terminal -e "gdb --pid %PID%"',
             '--option', 'interfaces=%s' % interfaces])
    t.port_wait("localhost", 445)

def test_smbclient(t):
    print('Testing smbclient')
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
    print("Adding test shares")
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
    print("Restarting bind9")
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
    print("Testing DNS")
    t.cmd_contains("host -t SRV _ldap._tcp.${LCREALM}.",
                 ['_ldap._tcp.${LCREALM} has SRV record 0 100 389 ${HOSTNAME}.${LCREALM}'])
    t.cmd_contains("host -t SRV  _kerberos._udp.${LCREALM}.",
                 ['_kerberos._udp.${LCREALM} has SRV record 0 100 88 ${HOSTNAME}.${LCREALM}'])
    t.cmd_contains("host -t A ${HOSTNAME}.${LCREALM}",
                 ['${HOSTNAME}.${LCREALM} has address'])

def test_kerberos(t):
    print("Testing kerberos")
    t.run_cmd("kdestroy")
    t.kinit("administrator@${REALM}", "${PASSWORD1}")
    t.cmd_contains("klist -e", ["Ticket cache", "Default principal", "Valid starting"])


def test_dyndns(t):
    t.chdir('${PREFIX}')
    t.cmd_contains("sbin/samba_dnsupdate", [])
    t.run_cmd("${RNDC} flush")
    t.cmd_contains("sbin/samba_dnsupdate --verbose", ["No DNS updates needed"])

def join_win7(t):
    print("Joining a Win7 box to the domain")
    t.vm_poweroff("${WINDOWS7_VM}", checkfail=False)
    t.vm_restore("${WINDOWS7_VM}", "${WINDOWS7_SNAPSHOT}")
    t.ping_wait("${WINDOWS7}")
    t.port_wait("${WINDOWS7}", 23)
    child = t.open_telnet("${WINDOWS7}", "administrator", "${PASSWORD1}", set_time=True)
    child.sendline("netdom join ${WINDOWS7} /Domain:${LCREALM} /PasswordD:${PASSWORD1} /UserD:administrator")
    child.expect("The computer needs to be restarted in order to complete the operation")
    child.expect("The command completed successfully")
    child.sendline("shutdown /r -t 0")
    t.port_wait("${WINDOWS7}", 23, wait_for_fail=True)
    t.port_wait("${WINDOWS7}", 23)


def test_win7(t):
    print("Checking the win7 join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WINDOWS7}", 445)
    t.retry_cmd('bin/smbclient -L ${WINDOWS7}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WINDOWS7}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -k no -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -k yes -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WINDOWS7}", 23)
    child = t.open_telnet("${WINDOWS7}", "${DOMAIN}\\administrator", "${PASSWORD1}")
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")
    t.vm_poweroff("${WINDOWS7_VM}")


def join_w2k8(t):
    print("Joining a w2k8 box to the domain as a DC")
    t.vm_poweroff("${WINDOWS_DC1_VM}", checkfail=False)
    t.vm_restore("${WINDOWS_DC1_VM}", "${WINDOWS_DC1_SNAPSHOT}")
    t.ping_wait("${WINDOWS_DC1}")
    t.port_wait("${WINDOWS_DC1}", 23)
    child = t.open_telnet("${WINDOWS_DC1}", "administrator", "${WINDOWS_DC1_PASS}")
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
    t.port_wait("${WINDOWS_DC1}", 23, wait_for_fail=True)
    t.port_wait("${WINDOWS_DC1}", 23)


def test_w2k8(t):
    print("Checking the w2k8 join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WINDOWS_DC1}", 445)
    t.retry_cmd('bin/smbclient -L ${WINDOWS_DC1}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WINDOWS_DC1}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WINDOWS_DC1}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WINDOWS_DC1}", 23)

    t.cmd_contains("bin/samba-tool drs kcc ${HOSTNAME} -Uadministrator@${LCREALM}%${PASSWORD1}", ['Consistency check', 'successful'])
    t.cmd_contains("bin/samba-tool drs kcc ${WINDOWS_DC1} -Uadministrator@${LCREALM}%${PASSWORD1}", ['Consistency check', 'successful'])

    t.kinit("administrator@${REALM}", "${PASSWORD1}")
    for nc in [ '${BASEDN}', 'CN=Configuration,${BASEDN}', 'CN=Schema,CN=Configuration,${BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WINDOWS_DC1} %s -k yes" % nc, ["was successful"])
        t.cmd_contains("bin/samba-tool drs replicate ${WINDOWS_DC1} ${HOSTNAME} %s -k yes" % nc, ["was successful"])

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

    t.cmd_contains("bin/samba-tool drs showrepl ${WINDOWS_DC1} -k yes",
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

    child = t.open_telnet("${WINDOWS_DC1}", "${DOMAIN}\\administrator", "${PASSWORD1}", set_time=True)
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")

    t.run_net_time(child)

    print("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${BASEDN}")
    child.expect("was successful")

    print("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    while True:
        i = child.expect(["The command completed successfully",
                          "The directory service was unable to allocate a relative identifier"])
        if i == 0:
            break
        time.sleep(2)

    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WINDOWS_DC1_VM}")


def join_w2k8_rodc(t):
    print("Joining a w2k8 box to the domain as a RODC")
    t.vm_poweroff("${WINDOWS_DC2_VM}", checkfail=False)
    t.vm_restore("${WINDOWS_DC2_VM}", "${WINDOWS_DC2_SNAPSHOT}")
    t.ping_wait("${WINDOWS_DC2}")
    t.port_wait("${WINDOWS_DC2}", 23)
    child = t.open_telnet("${WINDOWS_DC2}", "administrator", "${WINDOWS_DC2_PASS}")
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
    t.port_wait("${WINDOWS_DC2}", 23, wait_for_fail=True)
    t.port_wait("${WINDOWS_DC2}", 23)



def test_w2k8_rodc(t):
    print("Checking the w2k8 RODC join is OK")
    t.chdir('${PREFIX}')
    t.port_wait("${WINDOWS_DC2}", 445)
    t.retry_cmd('bin/smbclient -L ${WINDOWS_DC2}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${WINDOWS_DC2}.${LCREALM}.", ['has address'])
    t.cmd_contains('bin/smbclient -L ${WINDOWS_DC2}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    t.port_wait("${WINDOWS_DC2}", 23)
    child = t.open_telnet("${WINDOWS_DC2}", "${DOMAIN}\\administrator", "${PASSWORD1}", set_time=True)
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")

    print("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${BASEDN}")
    child.expect("was successful")

    print("Checking if new users are available on windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2}", ['LOGON_FAILURE'])
    t.vm_poweroff("${WINDOWS_DC2_VM}")


def vampire_w2k8(t):
    print("Joining w2k8 as a second DC")
    t.chdir('${PREFIX}')
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.vm_poweroff("${WINDOWS_DC3_VM}", checkfail=False)
    t.vm_restore("${WINDOWS_DC3_VM}", "${WINDOWS_DC3_SNAPSHOT}")
    t.run_cmd('${RNDC} flush')
    t.run_cmd("rm -rf etc private")
    t.open_telnet("${WINDOWS_DC3}", "${WINDOWS_DC3_DOMAIN}\\administrator", "${WINDOWS_DC3_PASS}", set_time=True)
    t.retry_cmd("bin/samba-tool drs showrepl ${WINDOWS_DC3} -Uadministrator%${WINDOWS_DC3_PASS}", ['INBOUND NEIGHBORS'] )
    t.run_cmd('bin/samba-tool join ${WINDOWS_DC3_REALM} DC -Uadministrator%${WINDOWS_DC3_PASS} -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC3} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')


def test_vampire(t):
    print("Checking the DC join is OK")
    t.chdir('${PREFIX}')
    t.retry_cmd('bin/smbclient -L ${HOSTNAME}.${WINDOWS_DC3_REALM} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${HOSTNAME}.${WINDOWS_DC3_REALM}.", ['has address'])
    t.port_wait("${WINDOWS_DC3}", 23)
    child = t.open_telnet("${WINDOWS_DC3}", "${WINDOWS_DC3_DOMAIN}\\administrator", "${WINDOWS_DC3_PASS}", set_time=True)

    print("Forcing kcc runs, and replication")
    t.run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC3} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')
    t.run_cmd('bin/samba-tool drs kcc ${HOSTNAME} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')

    t.kinit("administrator@${WINDOWS_DC3_REALM}", "${WINDOWS_DC3_PASS}")
    for nc in [ '${WINDOWS_DC3_BASEDN}', 'CN=Configuration,${WINDOWS_DC3_BASEDN}', 'CN=Schema,CN=Configuration,${WINDOWS_DC3_BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WINDOWS_DC3} %s -k yes" % nc, ["was successful"])
        t.cmd_contains("bin/samba-tool drs replicate ${WINDOWS_DC3} ${HOSTNAME} %s -k yes" % nc, ["was successful"])

    child.sendline("net use t: \\\\${HOSTNAME}.${WINDOWS_DC3_REALM}\\test")
    child.expect("The command completed successfully")

    print("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${WINDOWS_DC3_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${WINDOWS_DC3_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${WINDOWS_DC3_BASEDN}")
    child.expect("was successful")

    print("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WINDOWS_DC3_VM}")


def vampire_w2k3(t):
    print("Joining w2k3 as a second DC")
    t.chdir('${PREFIX}')
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.vm_poweroff("${WINDOWS_DC4_VM}", checkfail=False)
    t.vm_restore("${WINDOWS_DC4_VM}", "${WINDOWS_DC4_SNAPSHOT}")
    t.run_cmd('${RNDC} flush')
    t.run_cmd("rm -rf etc private")
    t.open_telnet("${WINDOWS_DC4}", "${WINDOWS_DC4_DOMAIN}\\administrator", "${WINDOWS_DC4_PASS}", set_time=True)
    t.retry_cmd("bin/samba-tool drs showrepl ${WINDOWS_DC4} -Uadministrator%${WINDOWS_DC4_PASS}", ['INBOUND NEIGHBORS'] )
    t.run_cmd('bin/samba-tool join ${WINDOWS_DC4_REALM} DC -Uadministrator%${WINDOWS_DC4_PASS} -d${DEBUGLEVEL}')
    t.run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC4} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')


def test_vampire_w2k3(t):
    print("Checking the DC join is OK")
    t.chdir('${PREFIX}')
    t.retry_cmd('bin/smbclient -L ${HOSTNAME}.${WINDOWS_DC4_REALM} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}', ["C$", "IPC$", "Sharename"])
    t.cmd_contains("host -t A ${HOSTNAME}.${WINDOWS_DC4_REALM}.", ['has address'])
    t.port_wait("${WINDOWS_DC4}", 23)
    child = t.open_telnet("${WINDOWS_DC4}", "${WINDOWS_DC4_DOMAIN}\\administrator", "${WINDOWS_DC4_PASS}", set_time=True)

    print("Forcing kcc runs, and replication")
    t.run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC4} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')
    t.run_cmd('bin/samba-tool drs kcc ${HOSTNAME} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')

    t.kinit("administrator@${WINDOWS_DC4_REALM}", "${WINDOWS_DC4_PASS}")
    for nc in [ '${WINDOWS_DC4_BASEDN}', 'CN=Configuration,${WINDOWS_DC4_BASEDN}', 'CN=Schema,CN=Configuration,${WINDOWS_DC4_BASEDN}' ]:
        t.cmd_contains("bin/samba-tool drs replicate ${HOSTNAME} ${WINDOWS_DC4} %s -k yes" % nc, ["was successful"])
        t.cmd_contains("bin/samba-tool drs replicate ${WINDOWS_DC4} ${HOSTNAME} %s -k yes" % nc, ["was successful"])

    child.sendline("net use t: \\\\${HOSTNAME}.${WINDOWS_DC4_REALM}\\test")
    child.expect("The command completed successfully")

    print("Checking if showrepl is happy")
    child.sendline("repadmin /showrepl")
    child.expect("${WINDOWS_DC4_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Configuration,${WINDOWS_DC4_BASEDN}")
    child.expect("was successful")
    child.expect("CN=Schema,CN=Configuration,${WINDOWS_DC4_BASEDN}")
    child.expect("was successful")

    print("Checking if new users propogate to windows")
    t.run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    t.run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['LOGON_FAILURE'])
    t.vm_poweroff("${WINDOWS_DC4_VM}")



opts, args = parser.parse_args()

if not opts.conf:
    print("Please specify a config file with --conf")
    sys.exit(1)

t = wintest.wintest()
t.load_config(opts.conf)

check_prerequesites(t)

build_s4(t)
provision_s4(t)
create_shares(t)
start_s4(t, interfaces='${INTERFACES}')
test_smbclient(t)
restart_bind(t)
test_dns(t)
test_kerberos(t)
test_dyndns(t)

join_win7(t)
test_win7(t)

join_w2k8_rodc(t)
test_w2k8_rodc(t)

join_w2k8(t)
test_w2k8(t)

vampire_w2k8(t)
create_shares(t)
start_s4(t, interfaces='${INTERFACES}')
test_dyndns(t)
test_vampire(t)

vampire_w2k3(t)
create_shares(t)
start_s4(t, interfaces='${INTERFACES}')
test_dyndns(t)
test_vampire_w2k3(t)

print("All OK")
