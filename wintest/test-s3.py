#!/usr/bin/env python

'''automated testing of Samba3 against windows'''

import sys, os
import optparse
import wintest

def check_prerequesites(t):
    t.info("Checking prerequesites")
    t.setvar('HOSTNAME', t.cmd_output("hostname -s").strip())
    if os.getuid() != 0:
        raise Exception("You must run this script as root")
    t.putenv("LD_LIBRARY_PATH", "${PREFIX}/lib")


def build_s3(t):
    '''build samba3'''
    t.info('Building s3')
    t.chdir('${SOURCETREE}/source3')
    t.putenv('CC', 'ccache gcc')
    t.run_cmd("./autogen.sh")
    t.run_cmd("./configure -C --prefix=${PREFIX} --enable-developer")
    t.run_cmd('make basics')
    t.run_cmd('make -j4')
    t.run_cmd('rm -rf ${PREFIX}')
    t.run_cmd('make install')

def start_s3(t, interfaces=None):
    t.info('Starting Samba3')
    t.chdir("${PREFIX}")
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.run_cmd("rm -f var/locks/*.pid")
    t.run_cmd(['sbin/nmbd', "-D"])
    t.run_cmd(['sbin/winbindd', "-D"])
    t.run_cmd(['sbin/smbd', "-D"])
    t.port_wait("localhost", 139)

def test_wbinfo(t):
    t.info('Testing wbinfo')
    t.chdir('${PREFIX}')
    t.cmd_contains("bin/wbinfo --version", ["Version 3."])
    t.cmd_contains("bin/wbinfo -p", ["Ping to winbindd succeeded"])
    t.retry_cmd("bin/wbinfo --online-status",
                ["BUILTIN : online",
                 "${HOSTNAME} : online",
                 "${WIN_DOMAIN} : online"],
                casefold=True)
    t.cmd_contains("bin/wbinfo -u",
                   ["${WIN_DOMAIN}/administrator",
                    "${WIN_DOMAIN}/krbtgt" ],
                   casefold=True)
    t.cmd_contains("bin/wbinfo -g",
                   ["${WIN_DOMAIN}/domain users",
                    "${WIN_DOMAIN}/domain guests",
                    "${WIN_DOMAIN}/domain admins"],
                   casefold=True)
    t.cmd_contains("bin/wbinfo --name-to-sid administrator",
                   "S-1-5-.*-500 SID_USER .1",
                   regex=True)
    t.cmd_contains("bin/wbinfo --name-to-sid 'domain users'",
                   "S-1-5-.*-513 SID_DOM_GROUP .2",
                   regex=True)

    t.retry_cmd("bin/wbinfo --authenticate=administrator%${WIN_PASS}",
                ["plaintext password authentication succeeded",
                 "challenge/response password authentication succeeded"])


def test_smbclient(t):
    t.info('Testing smbclient')
    t.chdir('${PREFIX}')
    t.cmd_contains("bin/smbclient --version", ["Version 3."])
    t.cmd_contains('bin/smbclient -L localhost -U%', ["Domain=[${WIN_DOMAIN}]", "test", "IPC$", "Samba 3."],
                   casefold=True)
    child = t.pexpect_spawn('bin/smbclient //${HOSTNAME}/test -Uadministrator%${WIN_PASS}')
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
    t.write_file("lib/smb.conf", '''
[test]
       path = ${PREFIX}/test
       read only = no
       ''',
                 mode='a')
    t.run_cmd("mkdir -p test")


def join_as_member(t, vm):
    '''join a windows domain as a member server'''
    t.setwinvars(vm)
    t.info("Joining ${WIN_VM} as a member using net ads join")
    t.chdir('${PREFIX}')
    t.run_cmd('killall -9 -q samba smbd nmbd winbindd', checkfail=False)
    t.vm_poweroff("${WIN_VM}", checkfail=False)
    t.vm_restore("${WIN_VM}", "${WIN_SNAPSHOT}")
    t.ping_wait("${WIN_HOSTNAME}")
    child = t.open_telnet("${WIN_HOSTNAME}", "administrator", "${WIN_PASS}", set_time=True)
    t.del_files(["var", "private"])
    t.write_file("lib/smb.conf", '''
[global]
	netbios name = ${HOSTNAME}
	log level = ${DEBUGLEVEL}
        realm = ${WIN_REALM}
        workgroup = ${WIN_DOMAIN}
        security = ADS
        interfaces = ${INTERFACES}
        winbind separator = /
        idmap uid = 1000000-2000000
        idmap gid = 1000000-2000000
        winbind enum users = yes
        winbind enum groups = yes
        max protocol = SMB2
        map hidden = no
        map system = no
        ea support = yes
        panic action = xterm -e gdb --pid %d
    ''')
    t.cmd_contains("bin/net ads join -Uadministrator%${WIN_PASS}", ["Joined"])
    t.cmd_contains("bin/net ads testjoin", ["Join is OK"])


def test_join_as_member(t, vm):
    '''test the domain join'''
    t.setwinvars(vm)
    t.info('Testing join as member')
    t.chdir('${PREFIX}')
    t.cmd_contains('bin/net ads user add root -Uadministrator%${WIN_PASS}')
    test_wbinfo(t)
    test_smbclient(t)


def test_s3(t):
    '''basic s3 testing'''

    check_prerequesites(t)

    # we don't need fsync safety in these tests
    t.putenv('TDB_NO_FSYNC', '1')

    if not t.skip("build"):
        build_s3(t)

    if t.have_var('W2K8R2A_VM') and not t.skip("join_w2k8r2"):
        join_as_member(t, "W2K8R2A")
        create_shares(t)
        start_s3(t, interfaces='${INTERFACES}')
        test_join_as_member(t, "W2K8R2A")

    t.info("S3 test: All OK")

if __name__ == '__main__':
    parser = optparse.OptionParser("test-howto.py")
    parser.add_option("--conf", type='string', default='', help='config file')
    parser.add_option("--skip", type='string', default='', help='list of steps to skip (comma separated)')
    parser.add_option("--list", action='store_true', default=False, help='list the available steps')
    parser.add_option("--rebase", action='store_true', default=False, help='do a git pull --rebase')
    parser.add_option("--clean", action='store_true', default=False, help='clean the tree')
    parser.add_option("--prefix", type='string', default=None, help='override install prefix')
    parser.add_option("--sourcetree", type='string', default=None, help='override sourcetree location')

    opts, args = parser.parse_args()

    if not opts.conf:
        print("Please specify a config file with --conf")
        sys.exit(1)

    t = wintest.wintest()
    t.load_config(opts.conf)
    t.set_skip(opts.skip)

    if opts.list:
        t.list_steps_mode()

    if opts.prefix:
        t.setvar('PREFIX', opts.prefix)

    if opts.sourcetree:
        t.setvar('SOURCETREE', opts.sourcetree)

    if opts.rebase:
        t.info('rebasing')
        t.chdir('${SOURCETREE}')
        t.run_cmd('git pull --rebase')

    if opts.clean:
        t.info('rebasing')
        t.chdir('${SOURCETREE}/source3')
        t.run_cmd('make clean')

    test_s3(t)
