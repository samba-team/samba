#!/usr/bin/env python

'''automated testing library for testing Samba against windows'''

import pexpect, subprocess
import sys, os, time, re

class wintest():
    '''testing of Samba against windows VMs'''

    def __init__(self):
        self.vars = {}
        self.list_mode = False
        self.vms = None
        os.putenv('PYTHONUNBUFFERED', '1')

    def setvar(self, varname, value):
        '''set a substitution variable'''
        self.vars[varname] = value

    def getvar(self, varname):
        '''return a substitution variable'''
        if not varname in self.vars:
            return None
        return self.vars[varname]

    def setwinvars(self, vm, prefix='WIN'):
        '''setup WIN_XX vars based on a vm name'''
        for v in ['VM', 'HOSTNAME', 'USER', 'PASS', 'SNAPSHOT', 'BASEDN', 'REALM', 'DOMAIN', 'IP']:
            vname = '%s_%s' % (vm, v)
            if vname in self.vars:
                self.setvar("%s_%s" % (prefix,v), self.substitute("${%s}" % vname))
            else:
                self.vars.pop("%s_%s" % (prefix,v), None)

    def info(self, msg):
        '''print some information'''
        if not self.list_mode:
            print(self.substitute(msg))

    def load_config(self, fname):
        '''load the config file'''
        f = open(fname)
        for line in f:
            line = line.strip()
            if len(line) == 0 or line[0] == '#':
                continue
            colon = line.find(':')
            if colon == -1:
                raise RuntimeError("Invalid config line '%s'" % line)
            varname = line[0:colon].strip()
            value   = line[colon+1:].strip()
            self.setvar(varname, value)

    def list_steps_mode(self):
        '''put wintest in step listing mode'''
        self.list_mode = True

    def set_skip(self, skiplist):
        '''set a list of tests to skip'''
        self.skiplist = skiplist.split(',')

    def set_vms(self, vms):
        '''set a list of VMs to test'''
        self.vms = vms.split(',')

    def skip(self, step):
        '''return True if we should skip a step'''
        if self.list_mode:
            print("\t%s" % step)
            return True
        return step in self.skiplist

    def substitute(self, text):
        """Substitute strings of the form ${NAME} in text, replacing
        with substitutions from vars.
        """
        if isinstance(text, list):
            ret = text[:]
            for i in range(len(ret)):
                ret[i] = self.substitute(ret[i])
            return ret

        """We may have objects such as pexpect.EOF that are not strings"""
        if not isinstance(text, str):
            return text
        while True:
            var_start = text.find("${")
            if var_start == -1:
                return text
            var_end = text.find("}", var_start)
            if var_end == -1:
                return text
            var_name = text[var_start+2:var_end]
            if not var_name in self.vars:
                raise RuntimeError("Unknown substitution variable ${%s}" % var_name)
            text = text.replace("${%s}" % var_name, self.vars[var_name])
        return text

    def have_var(self, varname):
        '''see if a variable has been set'''
        return varname in self.vars

    def have_vm(self, vmname):
        '''see if a VM should be used'''
        if not self.have_var(vmname + '_VM'):
            return False
        if self.vms is None:
            return True
        return vmname in self.vms

    def putenv(self, key, value):
        '''putenv with substitution'''
        os.putenv(key, self.substitute(value))

    def chdir(self, dir):
        '''chdir with substitution'''
        os.chdir(self.substitute(dir))

    def del_files(self, dirs):
        '''delete all files in the given directory'''
        for d in dirs:
            self.run_cmd("find %s -type f | xargs rm -f" % d)

    def write_file(self, filename, text, mode='w'):
        '''write to a file'''
        f = open(self.substitute(filename), mode=mode)
        f.write(self.substitute(text))
        f.close()

    def run_cmd(self, cmd, dir=".", show=None, output=False, checkfail=True):
        '''run a command'''
        cmd = self.substitute(cmd)
        if isinstance(cmd, list):
            self.info('$ ' + " ".join(cmd))
        else:
            self.info('$ ' + cmd)
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


    def run_child(self, cmd, dir="."):
        '''create a child and return the Popen handle to it'''
        cwd = os.getcwd()
        cmd = self.substitute(cmd)
        if isinstance(cmd, list):
            self.info('$ ' + " ".join(cmd))
        else:
            self.info('$ ' + cmd)
        if isinstance(cmd, list):
            shell=False
        else:
            shell=True
        os.chdir(dir)
        ret = subprocess.Popen(cmd, shell=shell, stderr=subprocess.STDOUT)
        os.chdir(cwd)
        return ret

    def cmd_output(self, cmd):
        '''return output from and command'''
        cmd = self.substitute(cmd)
        return self.run_cmd(cmd, output=True)

    def cmd_contains(self, cmd, contains, nomatch=False, ordered=False, regex=False,
                     casefold=False):
        '''check that command output contains the listed strings'''

        if isinstance(contains, str):
            contains = [contains]

        out = self.cmd_output(cmd)
        self.info(out)
        for c in self.substitute(contains):
            if regex:
                m = re.search(c, out)
                if m is None:
                    start = -1
                    end = -1
                else:
                    start = m.start()
                    end = m.end()
            elif casefold:
                start = out.upper().find(c.upper())
                end = start + len(c)
            else:
                start = out.find(c)
                end = start + len(c)
            if nomatch:
                if start != -1:
                    raise RuntimeError("Expected to not see %s in %s" % (c, cmd))
            else:
                if start == -1:
                    raise RuntimeError("Expected to see %s in %s" % (c, cmd))
            if ordered and start != -1:
                out = out[end:]

    def retry_cmd(self, cmd, contains, retries=30, delay=2, wait_for_fail=False,
                  ordered=False, regex=False, casefold=False):
        '''retry a command a number of times'''
        while retries > 0:
            try:
                self.cmd_contains(cmd, contains, nomatch=wait_for_fail,
                                  ordered=ordered, regex=regex, casefold=casefold)
                return
            except:
                time.sleep(delay)
                retries -= 1
                self.info("retrying (retries=%u delay=%u)" % (retries, delay))
        raise RuntimeError("Failed to find %s" % contains)

    def pexpect_spawn(self, cmd, timeout=60, crlf=True, casefold=True):
        '''wrapper around pexpect spawn'''
        cmd = self.substitute(cmd)
        self.info("$ " + cmd)
        ret = pexpect.spawn(cmd, logfile=sys.stdout, timeout=timeout)

        def sendline_sub(line):
            line = self.substitute(line)
            if crlf:
                line = line.replace('\n', '\r\n') + '\r'
            return ret.old_sendline(line)

        def expect_sub(line, timeout=ret.timeout, casefold=casefold):
            line = self.substitute(line)
            if casefold:
                if isinstance(line, list):
                    for i in range(len(line)):
                        if isinstance(line[i], str):
                            line[i] = '(?i)' + line[i]
                elif isinstance(line, str):
                    line = '(?i)' + line
            return ret.old_expect(line, timeout=timeout)

        ret.old_sendline = ret.sendline
        ret.sendline = sendline_sub
        ret.old_expect = ret.expect
        ret.expect = expect_sub

        return ret

    def get_nameserver(self):
        '''Get the current nameserver from /etc/resolv.conf'''
        child = self.pexpect_spawn('cat /etc/resolv.conf', crlf=False)
        i = child.expect(['Generated by wintest', 'nameserver'])
        if i == 0:
            child.expect('your original resolv.conf')
            child.expect('nameserver')
        child.expect('\d+.\d+.\d+.\d+')
        return child.after

    def vm_poweroff(self, vmname, checkfail=True):
        '''power off a VM'''
        self.setvar('VMNAME', vmname)
        self.run_cmd("${VM_POWEROFF}", checkfail=checkfail)

    def vm_reset(self, vmname):
        '''reset a VM'''
        self.setvar('VMNAME', vmname)
        self.run_cmd("${VM_RESET}")

    def vm_restore(self, vmname, snapshot):
        '''restore a VM'''
        self.setvar('VMNAME', vmname)
        self.setvar('SNAPSHOT', snapshot)
        self.run_cmd("${VM_RESTORE}")

    def ping_wait(self, hostname):
        '''wait for a hostname to come up on the network'''
        hostname = self.substitute(hostname)
        loops=10
        while loops > 0:
            try:
                self.run_cmd("ping -c 1 -w 10 %s" % hostname)
                break
            except:
                loops = loops - 1
        if loops == 0:
            raise RuntimeError("Failed to ping %s" % hostname)
        self.info("Host %s is up" % hostname)

    def port_wait(self, hostname, port, retries=200, delay=3, wait_for_fail=False):
        '''wait for a host to come up on the network'''
        self.retry_cmd("nc -v -z -w 1 %s %u" % (hostname, port), ['succeeded'],
                       retries=retries, delay=delay, wait_for_fail=wait_for_fail)

    def run_net_time(self, child):
        '''run net time on windows'''
        child.sendline("net time \\\\${HOSTNAME} /set")
        child.expect("Do you want to set the local computer")
        child.sendline("Y")
        child.expect("The command completed successfully")

    def run_date_time(self, child, time_tuple=None):
        '''run date and time on windows'''
        if time_tuple is None:
            time_tuple = time.localtime()
        child.sendline("date")
        child.expect("Enter the new date:")
        i = child.expect(["dd-mm-yy", "mm-dd-yy"])
        if i == 0:
            child.sendline(time.strftime("%d-%m-%y", time_tuple))
        else:
            child.sendline(time.strftime("%m-%d-%y", time_tuple))
        child.expect("C:")
        child.sendline("time")
        child.expect("Enter the new time:")
        child.sendline(time.strftime("%H:%M:%S", time_tuple))
        child.expect("C:")

    def get_ipconfig(self, child):
        '''get the IP configuration of the child'''
        child.sendline("ipconfig /all")
        child.expect('Ethernet adapter ')
        child.expect("[\w\s]+")
        self.setvar("WIN_NIC", child.after)
        child.expect(['IPv4 Address', 'IP Address'])
        child.expect('\d+.\d+.\d+.\d+')
        self.setvar('WIN_IPV4_ADDRESS', child.after)
        child.expect('Subnet Mask')
        child.expect('\d+.\d+.\d+.\d+')
        self.setvar('WIN_SUBNET_MASK', child.after)
        child.expect('Default Gateway')
        child.expect('\d+.\d+.\d+.\d+')
        self.setvar('WIN_DEFAULT_GATEWAY', child.after)
        child.expect("C:")

    def get_is_dc(self, child):
        child.sendline("dcdiag")
        i = child.expect(["is not a Directory Server", "Home Server = "])
        if i == 0:
            return False
        child.expect('[\S]+')
        hostname = child.after
        if hostname.upper() == self.getvar("WIN_HOSTNAME").upper:
            return True

    def run_tlntadmn(self, child):
        '''remove the annoying telnet restrictions'''
        child.sendline('tlntadmn config maxconn=1024')
        child.expect("The settings were successfully updated")
        child.expect("C:")

    def disable_firewall(self, child):
        '''remove the annoying firewall'''
        child.sendline('netsh advfirewall set allprofiles state off')
        i = child.expect(["Ok", "The following command was not found: advfirewall set allprofiles state off"])
        child.expect("C:")
        if i == 1:
            child.sendline('netsh firewall set opmode mode = DISABLE profile = ALL')
            i = child.expect(["Ok", "The following command was not found"])
            if i != 0:
                self.info("Firewall disable failed - ignoring")
            child.expect("C:")
 
    def set_dns(self, child):
        child.sendline('netsh interface ip set dns "${WIN_NIC}" static ${INTERFACE_IP} primary')
        i = child.expect(['C:', pexpect.EOF, pexpect.TIMEOUT], timeout=5)
        if i > 0:
            return True
        else:
            return False

    def set_ip(self, child):
        """fix the IP address to the same value it had when we
        connected, but don't use DHCP, and force the DNS server to our
        DNS server.  This allows DNS updates to run"""
        self.get_ipconfig(child)
        if self.getvar("WIN_IPV4_ADDRESS") != self.getvar("WIN_IP"):
            raise RuntimeError("ipconfig address %s != nmblookup address %s" % (self.getvar("WIN_IPV4_ADDRESS"),
                                                                                self.getvar("WIN_IP")))
        child.sendline('netsh')
        child.expect('netsh>')
        child.sendline('offline')
        child.expect('netsh>')
        child.sendline('routing ip add persistentroute dest=0.0.0.0 mask=0.0.0.0 name="${WIN_NIC}" nhop=${WIN_DEFAULT_GATEWAY}')
        child.expect('netsh>')
        child.sendline('interface ip set address "${WIN_NIC}" static ${WIN_IPV4_ADDRESS} ${WIN_SUBNET_MASK} ${WIN_DEFAULT_GATEWAY} 1 store=persistent')
        i = child.expect(['The syntax supplied for this command is not valid. Check help for the correct syntax', 'netsh>', pexpect.EOF, pexpect.TIMEOUT], timeout=5)
        if i == 0:
            child.sendline('interface ip set address "${WIN_NIC}" static ${WIN_IPV4_ADDRESS} ${WIN_SUBNET_MASK} ${WIN_DEFAULT_GATEWAY} 1')
            child.expect('netsh>')
        child.sendline('commit')
        child.sendline('online')
        child.sendline('exit')

        child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=5)
        return True


    def resolve_ip(self, hostname, retries=60, delay=5):
        '''resolve an IP given a hostname, assuming NBT'''
        while retries > 0:
            child = self.pexpect_spawn("bin/nmblookup %s" % hostname)
            i = child.expect(['\d+.\d+.\d+.\d+', "Lookup failed"])
            if i == 0:
                return child.after
            retries -= 1
            time.sleep(delay)
            self.info("retrying (retries=%u delay=%u)" % (retries, delay))
        raise RuntimeError("Failed to resolve IP of %s" % hostname)


    def open_telnet(self, hostname, username, password, retries=60, delay=5, set_time=False, set_ip=False,
                    disable_firewall=True, run_tlntadmn=True):
        '''open a telnet connection to a windows server, return the pexpect child'''
        set_route = False
        set_dns = False
        if self.getvar('WIN_IP'):
            ip = self.getvar('WIN_IP')
        else:
            ip = self.resolve_ip(hostname)
            self.setvar('WIN_IP', ip)
        while retries > 0:
            child = self.pexpect_spawn("telnet " + ip + " -l '" + username + "'")
            i = child.expect(["Welcome to Microsoft Telnet Service",
                              "Denying new connections due to the limit on number of connections",
                              "No more connections are allowed to telnet server",
                              "Unable to connect to remote host",
                              "No route to host",
                              "Connection refused",
                              pexpect.EOF])
            if i != 0:
                child.close()
                time.sleep(delay)
                retries -= 1
                self.info("retrying (retries=%u delay=%u)" % (retries, delay))
                continue
            child.expect("password:")
            child.sendline(password)
            i = child.expect(["C:",
                              "Denying new connections due to the limit on number of connections",
                              "No more connections are allowed to telnet server",
                              "Unable to connect to remote host",
                              "No route to host",
                              "Connection refused",
                              pexpect.EOF])
            if i != 0:
                child.close()
                time.sleep(delay)
                retries -= 1
                self.info("retrying (retries=%u delay=%u)" % (retries, delay))
                continue
            if set_dns:
                set_dns = False
                if self.set_dns(child):
                    continue;
            if set_route:
                child.sendline('route add 0.0.0.0 mask 0.0.0.0 ${WIN_DEFAULT_GATEWAY}')
                child.expect("C:")
                set_route = False
            if set_time:
                self.run_date_time(child, None)
                set_time = False
            if run_tlntadmn:
                self.run_tlntadmn(child)
                run_tlntadmn = False
            if disable_firewall:
                self.disable_firewall(child)
                disable_firewall = False
            if set_ip:
                set_ip = False
                if self.set_ip(child):
                    set_route = True
                    set_dns = True
                continue
            return child
        raise RuntimeError("Failed to connect with telnet")

    def kinit(self, username, password):
        '''use kinit to setup a credentials cache'''
        self.run_cmd("kdestroy")
        self.putenv('KRB5CCNAME', "${PREFIX}/ccache.test")
        username = self.substitute(username)
        s = username.split('@')
        if len(s) > 0:
            s[1] = s[1].upper()
        username = '@'.join(s)
        child = self.pexpect_spawn('kinit ' + username)
        child.expect("Password")
        child.sendline(password)
        child.expect(pexpect.EOF)
        child.close()
        if child.exitstatus != 0:
            raise RuntimeError("kinit failed with status %d" % child.exitstatus)

    def get_domains(self):
        '''return a dictionary of DNS domains and IPs for named.conf'''
        ret = {}
        for v in self.vars:
            if v[-6:] == "_REALM":
                base = v[:-6]
                if base + '_IP' in self.vars:
                    ret[self.vars[base + '_REALM']] = self.vars[base + '_IP']
        return ret

    def wait_reboot(self, retries=3):
        '''wait for a VM to reboot'''

        # first wait for it to shutdown
        self.port_wait("${WIN_IP}", 139, wait_for_fail=True, delay=6)

        # now wait for it to come back. If it fails to come back
        # then try resetting it
        while retries > 0:
            try:
                self.port_wait("${WIN_IP}", 139)
                return
            except:
                retries -= 1
                self.vm_reset("${WIN_VM}")
                self.info("retrying reboot (retries=%u)" % retries)
        raise RuntimeError(self.substitute("VM ${WIN_VM} failed to reboot"))

    def get_vms(self):
        '''return a dictionary of all the configured VM names'''
        ret = []
        for v in self.vars:
            if v[-3:] == "_VM":
                ret.append(self.vars[v])
        return ret
