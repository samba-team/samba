#!/usr/bin/env python

'''automated testing of the steps of the Samba4 HOWTO'''

import pexpect, subprocess
import sys, os, time
import optparse

vars = {}

parser = optparse.OptionParser("samba_dnsupdate")
parser.add_option("--conf", type='string', default='', help='config file')

def load_config(fname):
    '''load the config file'''
    f = open(fname)
    for line in f:
        line = line.strip()
        if len(line) == 0 or line[0] == '#':
            continue
        colon = line.find(':')
        if colon == -1:
            raise Exception("Invalid config line '%s'" % line)
        varname = line[0:colon].strip()
        value   = line[colon+1:].strip()
        vars[varname] = value

def substitute(text):
    """Substitute strings of the form ${NAME} in text, replacing
    with substitutions from vars.
    """
    if isinstance(text, list):
        ret = text[:]
        for i in range(len(ret)):
            ret[i] = substitute(ret[i])
        return ret

    while True:
        var_start = text.find("${")
        if var_start == -1:
            return text
        var_end = text.find("}", var_start)
        if var_end == -1:
            return text
        var_name = text[var_start+2:var_end]
        if not var_name in vars:
            raise Exception("Unknown substitution variable ${%s}" % var_name)
        text = text.replace("${%s}" % var_name, vars[var_name])
    return text



def putenv(key, value):
    os.putenv(key, substitute(value))

def chdir(dir):
    os.chdir(substitute(dir))


def run_cmd(cmd, dir=".", show=None, output=False, checkfail=True):
    cmd = substitute(cmd)
    if isinstance(cmd, list):
        print('$ ' + " ".join(cmd))
    else:
        print('$ ' + cmd)
    if output:
        return subprocess.Popen([cmd], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=dir).communicate()[0]
    if isinstance(cmd, list):
        shell=False
    else:
        shell=True
    if checkfail:
        return subprocess.check_call(cmd, shell=shell, cwd=dir)
    else:
        return subprocess.call(cmd, shell=shell, cwd=dir)


def cmd_output(cmd):
    '''return output from and command'''
    cmd = substitute(cmd)
    return run_cmd(cmd, output=True)

def cmd_contains(cmd, contains, nomatch=False):
    '''check that command output contains the listed strings'''
    out = cmd_output(cmd)
    print out
    for c in substitute(contains):
        if nomatch:
            if out.find(c) != -1:
                raise Exception("Expected to not see %s in %s" % (c, cmd))
        else:
            if out.find(c) == -1:
                raise Exception("Expected to see %s in %s" % (c, cmd))

def retry_cmd(cmd, contains, retries=30, delay=2, wait_for_fail=False):
    '''retry a command a number of times'''
    while retries > 0:
        try:
            cmd_contains(cmd, contains, nomatch=wait_for_fail)
            return
        except:
            time.sleep(delay)
            retries = retries - 1
    raise Exception("Failed to find %s" % contains)

def pexpect_spawn(cmd, timeout=60):
    '''wrapper around pexpect spawn'''

    cmd = substitute(cmd)
    print("$ " + cmd)
    ret = pexpect.spawn(cmd, logfile=sys.stdout, timeout=timeout)

    def sendline_sub(line):
        line = substitute(line).replace('\n', '\r\n')
        return ret.old_sendline(line + '\r')

    def expect_sub(line, timeout=ret.timeout):
        line = substitute(line)
        return ret.old_expect(line, timeout=timeout)

    ret.old_sendline = ret.sendline
    ret.sendline = sendline_sub
    ret.old_expect = ret.expect
    ret.expect = expect_sub

    return ret

def vm_poweroff(vmname, checkfail=True):
    '''power off a VM'''
    vars['VMNAME'] = vmname
    run_cmd("${VM_POWEROFF}", checkfail=checkfail)

def vm_restore(vmname, snapshot):
    '''restore a VM'''
    vars['VMNAME'] = vmname
    vars['SNAPSHOT'] = snapshot
    run_cmd("${VM_RESTORE}")

def ping_wait(hostname):
    '''wait for a hostname to come up on the network'''
    hostname=substitute(hostname)
    loops=10
    while loops > 0:
        try:
            run_cmd("ping -c 1 -w 10 %s" % hostname)
            break
        except:
            loops = loops - 1
    if loops == 0:
        raise Exception("Failed to ping %s" % hostname)
    print("Host %s is up" % hostname)

def port_wait(hostname, port, retries=100, delay=2, wait_for_fail=False):
    '''wait for a host to come up on the network'''
    retry_cmd("nc -v -z -w 1 %s %u" % (hostname, port), ['succeeded'],
              retries=retries, delay=delay, wait_for_fail=wait_for_fail)


def check_prerequesites():
    print("Checking prerequesites")
    vars['HOSTNAME'] = cmd_output("hostname -s").strip()
    if os.getuid() != 0:
        raise Exception("You must run this script as root")
    cmd_contains("grep 127.0.0.1 /etc/resolv.conf", ["nameserver 127.0.0.1"])

def build_s4(prefix=None):
    '''build samba4'''
    print('Building s4')
    chdir('${SOURCETREE}/source4')
    putenv('CC', 'ccache gcc')
    run_cmd('make reconfigure || ./configure --enable-auto-reconfigure --enable-developer --prefix=${PREFIX} -C')
    run_cmd('make -j')
    run_cmd('rm -rf ${PREFIX}')
    run_cmd('make -j install')

def provision_s4():
    '''provision s4 as a DC'''
    print('Provisioning s4')
    chdir('${PREFIX}')
    run_cmd("rm -rf etc private")
    run_cmd('sbin/provision --realm=${LCREALM} --domain=${DOMAIN} --adminpass=${PASSWORD1} --server-role="domain controller" --function-level=2008')
    run_cmd('bin/samba-tool newuser testallowed ${PASSWORD1}')
    run_cmd('bin/samba-tool newuser testdenied ${PASSWORD1}')
    run_cmd('bin/samba-tool group addmembers "Allowed RODC Password Replication Group" testallowed')

def start_s4(prefix=None, interfaces=None):
    print('Starting Samba4')
    chdir(prefix)
    run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    run_cmd(['sbin/samba',
             '--option', 'panic action=gnome-terminal -e "gdb --pid %PID%"',
             '--option', 'interfaces=%s' % interfaces])
    port_wait("localhost", 445)

def test_smbclient():
    print('Testing smbclient')
    chdir('${PREFIX}')
    cmd_contains("bin/smbclient --version", ["Version 4.0"])
    cmd_contains('bin/smbclient -L localhost -U%', ["netlogon", "sysvol", "IPC Service"])
    child = pexpect_spawn('bin/smbclient //localhost/netlogon -Uadministrator%${PASSWORD1}')
    child.expect("smb:")
    child.sendline("dir")
    child.expect("blocks available")
    child.sendline("mkdir testdir")
    child.expect("smb:")
    child.sendline("cd testdir")
    child.expect('testdir')
    child.sendline("cd ..")
    child.sendline("rmdir testdir")

def create_shares():
    print("Adding test shares")
    chdir('${PREFIX}')
    f = open("etc/smb.conf", mode='a')
    f.write(substitute('''
[test]
       path = ${PREFIX}/test
       read only = no
[profiles]
       path = ${PREFIX}/var/profiles
       read only = no
    '''))
    f.close()
    run_cmd("mkdir -p test")
    run_cmd("mkdir -p var/profiles")


def restart_bind():
    print("Restarting bind9")
    putenv('KEYTAB_FILE', '${PREFIX}/private/dns.keytab')
    putenv('KRB5_KTNAME', '${PREFIX}/private/dns.keytab')
    run_cmd('killall -9 -q named', checkfail=False)
    port_wait("localhost", 53, wait_for_fail=True)
    run_cmd("${BIND9}")
    port_wait("localhost", 53)
    run_cmd("${RNDC} flush")
    run_cmd("${RNDC} freeze")
    run_cmd("${RNDC} thaw")

def test_dns():
    print("Testing DNS")
    cmd_contains("host -t SRV _ldap._tcp.${LCREALM}.",
                 ['_ldap._tcp.${LCREALM} has SRV record 0 100 389 ${HOSTNAME}.${LCREALM}'])
    cmd_contains("host -t SRV  _kerberos._udp.${LCREALM}.",
                 ['_kerberos._udp.${LCREALM} has SRV record 0 100 88 ${HOSTNAME}.${LCREALM}'])
    cmd_contains("host -t A ${HOSTNAME}.${LCREALM}",
                 ['${HOSTNAME}.${LCREALM} has address'])

def test_kerberos():
    print("Testing kerberos")
    run_cmd("kdestroy")
    child = pexpect_spawn('kinit -V administrator@${REALM}')
    child.expect("Password for")
    child.sendline("${PASSWORD1}")
    child.expect("Authenticated to Kerberos")
    cmd_contains("klist -e", ["Ticket cache", "Default principal", "Valid starting"])

def test_dyndns():
    chdir('${PREFIX}')
    cmd_contains("sbin/samba_dnsupdate", [])
    run_cmd("${RNDC} flush")
    cmd_contains("sbin/samba_dnsupdate --verbose", ["No DNS updates needed"])

def join_win7():
    print("Joining a Win7 box to the domain")
    vm_poweroff("${WINDOWS7_VM}", checkfail=False)
    vm_restore("${WINDOWS7_VM}", "${WINDOWS7_SNAPSHOT}")
    ping_wait("${WINDOWS7}")
    port_wait("${WINDOWS7}", 23)
    child = pexpect_spawn("telnet ${WINDOWS7} -l administrator")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${PASSWORD1}")
    child.expect("C:")
    child.sendline("netdom join ${WINDOWS7} /Domain:${LCREALM} /PasswordD:${PASSWORD1} /UserD:administrator")
    child.expect("The computer needs to be restarted in order to complete the operation")
    child.expect("The command completed successfully")
    child.sendline("shutdown /r -t 0")
    port_wait("${WINDOWS7}", 23, wait_for_fail=True)
    port_wait("${WINDOWS7}", 23)


def test_win7():
    print("Checking the win7 join is OK")
    chdir('${PREFIX}')
    port_wait("${WINDOWS7}", 445)
    retry_cmd('bin/smbclient -L ${WINDOWS7}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    cmd_contains("host -t A ${WINDOWS7}.${LCREALM}.", ['has address'])
    cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -k no -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    cmd_contains('bin/smbclient -L ${WINDOWS7}.${LCREALM} -k yes -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    port_wait("${WINDOWS7}", 23)
    child = pexpect_spawn("telnet ${WINDOWS7} -l '${DOMAIN}\\administrator'")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${PASSWORD1}")
    child.expect("C:")
    child.sendline("net use t: \\\\${HOSTNAME}.${LCREALM}\\test")
    child.expect("The command completed successfully")
    vm_poweroff("${WINDOWS7_VM}")


def join_w2k8():
    print("Joining a w2k8 box to the domain as a DC")
    vm_poweroff("${WINDOWS_DC1_VM}", checkfail=False)
    vm_restore("${WINDOWS_DC1_VM}", "${WINDOWS_DC1_SNAPSHOT}")
    ping_wait("${WINDOWS_DC1}")
    port_wait("${WINDOWS_DC1}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC1} -l administrator")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${WINDOWS_DC1_PASS}")
    child.expect("C:")
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
    port_wait("${WINDOWS_DC1}", 23, wait_for_fail=True)
    port_wait("${WINDOWS_DC1}", 23)


def test_w2k8():
    print("Checking the w2k8 join is OK")
    chdir('${PREFIX}')
    port_wait("${WINDOWS_DC1}", 445)
    retry_cmd('bin/smbclient -L ${WINDOWS_DC1}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    cmd_contains("host -t A ${WINDOWS_DC1}.${LCREALM}.", ['has address'])
    cmd_contains('bin/smbclient -L ${WINDOWS_DC1}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    port_wait("${WINDOWS_DC1}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC1} -l '${DOMAIN}\\administrator'")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${PASSWORD1}")
    child.expect("C:")
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

    print("Checking if new users propogate to windows")
    run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    while True:
        i = child.expect(["The command completed successfully",
                          "The directory service was unable to allocate a relative identifier"])
        if i == 0:
            break
        time.sleep(2)

    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['Sharename', 'IPC'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest3%${PASSWORD3} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    vm_poweroff("${WINDOWS_DC1_VM}")


def join_w2k8_rodc():
    print("Joining a w2k8 box to the domain as a RODC")
    vm_poweroff("${WINDOWS_DC2_VM}", checkfail=False)
    vm_restore("${WINDOWS_DC2_VM}", "${WINDOWS_DC2_SNAPSHOT}")
    ping_wait("${WINDOWS_DC2}")
    port_wait("${WINDOWS_DC2}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC2} -l administrator")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${WINDOWS_DC2_PASS}")
    child.expect("C:")
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
    port_wait("${WINDOWS_DC2}", 23, wait_for_fail=True)
    port_wait("${WINDOWS_DC2}", 23)



def test_w2k8_rodc():
    print("Checking the w2k8 RODC join is OK")
    chdir('${PREFIX}')
    port_wait("${WINDOWS_DC2}", 445)
    retry_cmd('bin/smbclient -L ${WINDOWS_DC2}.${LCREALM} -Uadministrator@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    cmd_contains("host -t A ${WINDOWS_DC2}.${LCREALM}.", ['has address'])
    cmd_contains('bin/smbclient -L ${WINDOWS_DC2}.${LCREALM} -Utestallowed@${LCREALM}%${PASSWORD1}', ["C$", "IPC$", "Sharename"])
    port_wait("${WINDOWS_DC2}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC2} -l '${DOMAIN}\\administrator'")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${PASSWORD1}")
    child.expect("C:")
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
    run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])
    run_cmd('bin/samba-tool user delete test2 -Uadministrator@${LCREALM}%${PASSWORD1}')
    retry_cmd("bin/smbclient -L ${WINDOWS_DC2} -Utest2%${PASSWORD2}", ['LOGON_FAILURE'])
    vm_poweroff("${WINDOWS_DC2_VM}")


def vampire_w2k8():
    print("Joining w2k8 as a second DC")
    chdir('${PREFIX}')
    run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    vm_poweroff("${WINDOWS_DC3_VM}", checkfail=False)
    vm_restore("${WINDOWS_DC3_VM}", "${WINDOWS_DC3_SNAPSHOT}")
    run_cmd('${RNDC} flush')
    run_cmd("rm -rf etc private")
    retry_cmd("bin/samba-tool drs showrepl ${WINDOWS_DC3} -Uadministrator%${WINDOWS_DC3_PASS}", ['INBOUND NEIGHBORS'] )
    run_cmd('bin/samba-tool join ${WINDOWS_DC3_REALM} DC -Uadministrator%${WINDOWS_DC3_PASS}')
    run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC3} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')


def test_vampire():
    print("Checking the DC join is OK")
    chdir('${PREFIX}')
    retry_cmd('bin/smbclient -L ${HOSTNAME}.${WINDOWS_DC3_REALM} -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}', ["C$", "IPC$", "Sharename"])
    cmd_contains("host -t A ${HOSTNAME}.${WINDOWS_DC3_REALM}.", ['has address'])
    port_wait("${WINDOWS_DC3}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC3} -l '${WINDOWS_DC3_DOMAIN}\\administrator'")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${WINDOWS_DC3_PASS}")
    child.expect("C:")
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
    run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC3} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WINDOWS_DC3_REALM}%${WINDOWS_DC3_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    vm_poweroff("${WINDOWS_DC3_VM}")


def vampire_w2k3():
    print("Joining w2k3 as a second DC")
    chdir('${PREFIX}')
    run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    vm_poweroff("${WINDOWS_DC4_VM}", checkfail=False)
    vm_restore("${WINDOWS_DC4_VM}", "${WINDOWS_DC4_SNAPSHOT}")
    run_cmd('${RNDC} flush')
    run_cmd("rm -rf etc private")
    retry_cmd("bin/samba-tool drs showrepl ${WINDOWS_DC4} -Uadministrator%${WINDOWS_DC4_PASS}", ['INBOUND NEIGHBORS'] )
    run_cmd('bin/samba-tool join ${WINDOWS_DC4_REALM} DC -Uadministrator%${WINDOWS_DC4_PASS} -d1')
    run_cmd('bin/samba-tool drs kcc ${WINDOWS_DC4} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')


def test_vampire_w2k3():
    print("Checking the DC join is OK")
    chdir('${PREFIX}')
    retry_cmd('bin/smbclient -L ${HOSTNAME}.${WINDOWS_DC4_REALM} -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}', ["C$", "IPC$", "Sharename"])
    cmd_contains("host -t A ${HOSTNAME}.${WINDOWS_DC4_REALM}.", ['has address'])
    port_wait("${WINDOWS_DC4}", 23)
    child = pexpect_spawn("telnet ${WINDOWS_DC4} -l '${WINDOWS_DC4_DOMAIN}\\administrator'")
    child.expect("Welcome to Microsoft Telnet Service")
    child.expect("password:")
    child.sendline("${WINDOWS_DC4_PASS}")
    child.expect("C:")
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
    run_cmd('bin/samba-tool newuser test2 ${PASSWORD2}')
    retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k no", ['Sharename', 'Remote IPC'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC4} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'Remote IPC'])

    print("Checking if new users on windows propogate to samba")
    child.sendline("net user test3 ${PASSWORD3} /add")
    child.expect("The command completed successfully")
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['Sharename', 'IPC'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['Sharename', 'IPC'])

    print("Checking propogation of user deletion")
    run_cmd('bin/samba-tool user delete test2 -Uadministrator@${WINDOWS_DC4_REALM}%${WINDOWS_DC4_PASS}')
    child.sendline("net user test3 /del")
    child.expect("The command completed successfully")

    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k no", ['LOGON_FAILURE'])
    retry_cmd("bin/smbclient -L ${WINDOWS_DC1} -Utest2%${PASSWORD2} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    retry_cmd("bin/smbclient -L ${HOSTNAME} -Utest2%${PASSWORD2} -k yes", ['NT_STATUS_UNSUCCESSFUL'])
    vm_poweroff("${WINDOWS_DC4_VM}")



os.putenv('PYTHONUNBUFFERED', '1')

opts, args = parser.parse_args()

if not opts.conf:
    print("Please specify a config file with --conf")
    sys.exit(1)

load_config(opts.conf)

check_prerequesites()
build_s4('${PREFIX}')
provision_s4()
create_shares()
start_s4('${PREFIX}', interfaces='${INTERFACES}')
test_smbclient()
restart_bind()
test_dns()
test_kerberos()
test_dyndns()

join_win7()
test_win7()

join_w2k8_rodc()
test_w2k8_rodc()

join_w2k8()
test_w2k8()

vampire_w2k8()
create_shares()
start_s4('${PREFIX}', interfaces='${INTERFACES}')
test_dyndns()
test_vampire()

vampire_w2k3()
create_shares()
start_s4('${PREFIX}', interfaces='${INTERFACES}')
test_dyndns()
test_vampire_w2k3()

print("All OK")
