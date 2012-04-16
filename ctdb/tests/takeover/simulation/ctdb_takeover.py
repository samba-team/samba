#!/usr/bin/env python

# ctdb ip takeover code

# Copyright (C) Martin Schwenke, Ronnie Sahlberg 2010, 2011

# Based on original CTDB C code:
#
# Copyright (C) Ronnie Sahlberg  2007
# Copyright (C) Andrew Tridgell  2007

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.


import os
import sys
# Use optparse since newer argparse not available in RHEL5/EPEL.
from optparse import OptionParser
import copy
import random
import itertools

# For parsing IP addresses
import socket
import struct

# For external algorithm
import subprocess
import re

options = None

def process_args(extra_options=[]):
    global options

    parser = OptionParser(option_list=extra_options)

    parser.add_option("--nd",
                      action="store_false", dest="deterministic_public_ips",
                      default=True,
                      help="turn off deterministic_public_ips")
    parser.add_option("--ni",
                      action="store_true", dest="no_ip_failback", default=False,
                      help="turn on no_ip_failback")
    parser.add_option("-L", "--lcp2",
                      action="store_true", dest="lcp2", default=False,
                      help="use LCP2 IP rebalancing algorithm [default: %default]")
    parser.add_option("-e", "--external",
                      action="store_true", dest="external", default=False,
                      help="use external test program to implement IP allocation algorithm [default: %default]")
    parser.add_option("-b", "--balance",
                      action="store_true", dest="balance", default=False,
                      help="show (im)balance information after each event")
    parser.add_option("-d", "--diff",
                      action="store_true", dest="diff", default=False,
                      help="show IP address movements for each event")
    parser.add_option("-n", "--no-print",
                      action="store_false", dest="show", default=True,
                      help="don't show IP address layout after each event")
    parser.add_option("-v", "--verbose",
                      action="count", dest="verbose", default=0,
                      help="print information and actions taken to stdout")
    parser.add_option("-r", "--retries",
                      action="store", type="int", dest="retries", default=5,
                      help="number of retry loops for rebalancing non-deterministic failback [default: %default]")
    parser.add_option("-i", "--iterations",
                      action="store", type="int", dest="iterations",
                      default=1000,
                      help="number of iterations to run in test [default: %default]")
    parser.add_option("-o", "--odds",
                      action="store", type="int", dest="odds", default=4,
                      help="make the chances of a failover 1 in ODDS [default: %default]")
    parser.add_option("-A", "--aggressive",
                      action="store_true", dest="aggressive", default=False,
                      help="apply ODDS to try to flip each node [default: %default]")

    def seed_callback(option, opt, value, parser):
        random.seed(value)
    parser.add_option("-s", "--seed",
                      action="callback", type="int", callback=seed_callback,
                      help="initial random number seed for random events")

    parser.add_option("-x", "--exit",
                      action="store_true", dest="exit", default=False,
                      help="exit on the 1st gratuitous IP move or IP imbalance")
    parser.add_option("-H", "--hard-imbalance-limit",
                      action="store", type="int", dest="hard_limit", default=1,
                      help="exceeding this limit causes termination  [default: %default]")
    parser.add_option("-S", "--soft-imbalance-limit",
                      action="store", type="int", dest="soft_limit", default=1,
                      help="exceeding this limit increments a counter [default: %default]")

    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.error("too many arguments")

    # Could use a callback for this or change the default, but
    # laziness is sometimes a virtue.  ;-)
    if options.lcp2:
        options.deterministic_public_ips = False

def print_begin(t, delim='='):
    print delim * 40
    print "%s:" % (t)

def print_end():
    print "-" * 40

def verbose_begin(t):
    if options.verbose > 0:
        print_begin(t)

def verbose_end():
    if options.verbose > 0:
        print_end()

def verbose_print(t):
    if options.verbose > 0:
        if not type(t) == list:
            t = [t]
        if t != []:
            print "\n".join([str(i) for i in t])

# more than this and we switch to the logging module...  :-)
def debug_begin(t):
    if options.verbose > 1:
        print_begin(t, '-')

def debug_end():
    if options.verbose > 1:
        print_end()

def debug_print(t):
    if options.verbose > 1:
        if not type(t) == list:
            t = [t]
        if t != []:
            print "\n".join([str(i) for i in t])

def ip_to_list_of_ints(ip):
    # Be lazy... but only expose errors in IPv4 addresses, since
    # they'll be more commonly used.  :-)
    try:
        l = socket.inet_pton(socket.AF_INET6, ip)
    except:
        # Pad with leading 0s.  This makes IPv4 addresses comparable
        # with IPv6 but reduces the overall effectiveness of the
        # algorithm.  The alternative would be to treat these
        # addresses separately while trying to keep all the IPs in
        # overall balance.
        l = "".join(itertools.repeat("\0", 12)) + \
            socket.inet_pton(socket.AF_INET, ip)

    return map(lambda x: struct.unpack('B', x)[0], l)

def ip_distance(ip1, ip2):
    """Calculate the distance between 2 IPs.

    This is the length of the longtest common prefix between the IPs.
    It is calculated by XOR-ing the 2 IPs together and counting the
    number of leading zeroes."""

    distance = 0
    for (o1, o2) in zip(ip_to_list_of_ints(ip1), ip_to_list_of_ints(ip2)):
        # XOR this pair of octets
        x = o1 ^ o2
        # count number leading zeroes
        if x == 0:
            distance += 8
        else:
            # bin() gives minimal length '0bNNN' string
            distance += (8 - (len(bin(x)) - 2))
            break

    return distance

def ip_distance_2_sum(ip, ips):
    """Calculate the IP distance for the given IP relative to IPs.

    This could be made more efficient by insering ip_distance_2 into
    the loop in this function.  However, that would result in some
    loss of clarity and also will not be necessary in a C
    implemntation."""

    sum = 0
    for i in ips:
        sum += ip_distance(ip, i) ** 2

    return sum

def imbalance_metric(ips):
    """Return the imbalance metric for a group of IPs.

    This is the sum of squares of the IP distances between each pair of IPs."""
    if len(ips) > 1:
        (h, t) = (ips[0], ips[1:])
        return ip_distance_2_sum(h, t) + imbalance_metric(t)
    else:
        return 0

def mean(l):
    return float(sum(l))/len(l)

class Node(object):
    def __init__(self, public_addresses):
        # List of list allows groups of IPs to be passed in.  They're
        # not actually used in the algorithm but are just used by
        # calculate_imbalance() for checking the simulation.  Note
        # that people can pass in garbage and make this code
        # fail... but we're all friends here in simulation world...
        # :-)
        if type(public_addresses[0]) is str:
            self.public_addresses = set(public_addresses)
            self.ip_groups = []
        else:
            # flatten
            self.public_addresses = set([i for s in public_addresses for i in s])
            self.ip_groups = public_addresses

        self.current_addresses = set()
        self.healthy = True
        self.imbalance = -1

    def __str__(self):
        return "%s %s%s" % \
            ("*" if len(self.public_addresses) == 0 else \
                 (" " if self.healthy else "#"),
             sorted(list(self.current_addresses)),
             " %d" % self.imbalance if options.lcp2 else "")

    def can_node_serve_ip(self, ip):
        return ip in self.public_addresses

    def node_ip_coverage(self, ips=None):
        return len([a for a in self.current_addresses if ips == None or a in ips])

    def set_imbalance(self, imbalance=-1):
        """Set the imbalance metric to the given value.  If none given
        then calculate it."""

        if imbalance != -1:
            self.imbalance = imbalance
        else:
            self.imbalance = imbalance_metric(list(self.current_addresses))

    def get_imbalance(self):
        return self.imbalance

class Cluster(object):
    def __init__(self):
        self.nodes = []
        self.deterministic_public_ips = options.deterministic_public_ips
        self.no_ip_failback = options.no_ip_failback
        self.all_public_ips = set()

        # Statistics
        self.ip_moves = []
        self.grat_ip_moves = []
        self.imbalance = []
        self.imbalance_groups = []
        self.imbalance_count = 0
        self.imbalance_groups_count = itertools.repeat(0)
        self.imbalance_metric = []
        self.events = -1
        self.num_unhealthy = []

        self.prev = None

    def __str__(self):
        return "\n".join(["%2d %s" % (i, n) \
                              for (i, n) in enumerate(self.nodes)])

    # This is naive.  It assumes that IP groups are indicated by the
    # 1st node having IP groups.
    def have_ip_groups(self):
        return (len(self.nodes[0].ip_groups) > 0)

    def print_statistics(self):
        print_begin("STATISTICS")
        print "Events:                      %6d" % self.events
        print "Total IP moves:              %6d" % sum(self.ip_moves)
        print "Gratuitous IP moves:         %6d" % sum(self.grat_ip_moves)
        print "Max imbalance:               %6d" % max(self.imbalance)
        if self.have_ip_groups():
            print "Max group imbalance counts:    ", map(max, zip(*self.imbalance_groups))
        print "Mean imbalance:              %f" % mean(self.imbalance)
        if self.have_ip_groups():
            print "Mean group imbalances counts:   ", map(mean, zip(*self.imbalance_groups))
        print "Final imbalance:             %6d" % self.imbalance[-1]
        if self.have_ip_groups():
            print "Final group imbalances:         ", self.imbalance_groups[-1]
        if options.lcp2:
            print "Max LCP2 imbalance  :        %6d" % max(self.imbalance_metric)
        print "Soft imbalance count:        %6d" % self.imbalance_count
        if self.have_ip_groups():
            print "Soft imbalance group counts:    ", self.imbalance_groups_count
        if options.lcp2:
            print "Final LCP2 imbalance  :      %6d" % self.imbalance_metric[-1]
        print "Maximum unhealthy:           %6d" % max(self.num_unhealthy)
        print_end()

    def find_pnn_with_ip(self, ip):
        for (i, n) in enumerate(self.nodes):
            if ip in n.current_addresses:
                return i
        return -1

    def quietly_remove_ip(self, ip):
        # Remove address from old node.
        old = self.find_pnn_with_ip(ip)
        if old != -1:
            self.nodes[old].current_addresses.remove(ip)

    def add_node(self, node):
        self.nodes.append(node)
        self.all_public_ips |= node.public_addresses

    def healthy(self, *pnns):
        verbose_begin("HEALTHY")

        for pnn in pnns:
            self.nodes[pnn].healthy = True
            verbose_print(pnn)

        verbose_end()

    def unhealthy(self, *pnns):

        verbose_begin("UNHEALTHY")

        for pnn in pnns:
            self.nodes[pnn].healthy = False
            verbose_print(pnn)

        verbose_end()

    def do_something_random(self):

        """Make random node(s) healthy or unhealthy.

        If options.aggressive is False then: If all nodes are healthy
        or unhealthy, then invert one of them; otherwise, there's a 1
        in options.odds chance of making another node unhealthy.

        If options.aggressive is True then: For each node there is a 1
        in options.odds chance of flipping the state of that node
        between healthy and unhealthy."""

        if not options.aggressive:
            num_nodes = len(self.nodes)
            healthy_pnns = [i for (i,n) in enumerate(self.nodes) if n.healthy]
            num_healthy = len(healthy_pnns)

            if num_nodes == num_healthy:
                self.unhealthy(random.randint(0, num_nodes-1))
            elif num_healthy == 0:
                self.healthy(random.randint(0, num_nodes-1))
            elif random.randint(1, options.odds) == 1:
                self.unhealthy(random.choice(healthy_pnns))
            else:
                all_pnns = range(num_nodes)
                unhealthy_pnns = sorted(list(set(all_pnns) - set(healthy_pnns)))
                self.healthy(random.choice(unhealthy_pnns))
        else:
            # We need to make at least one change or we retry...x
            changed = False
            while not changed:
                for (pnn, n) in enumerate(self.nodes):
                    if random.randint(1, options.odds) == 1:
                        changed = True
                        if n.healthy:
                            self.unhealthy(pnn)
                        else:
                            self.healthy(pnn)

    def random_iterations(self):
        i = 1
        while i <= options.iterations:
            verbose_begin("EVENT %d" % i)
            verbose_end()
            self.do_something_random()
            if self.recover() and options.exit:
                break
            i += 1

        self.print_statistics()

    def imbalance_for_ips(self, ips):

        imbalance = 0

        maxnode = -1
        minnode = -1

        for ip in ips:
            for (i, n) in enumerate(self.nodes):

                if not n.healthy or not n.can_node_serve_ip(ip):
                    continue

                num = n.node_ip_coverage(ips)

                if maxnode == -1 or num > maxnum:
                    maxnode = i
                    maxnum = num

                if minnode == -1 or num < minnum:
                    minnode = i
                    minnum = num

            if maxnode == -1 or minnode == -1:
                continue

            i = maxnum - minnum
            #if i < 2:
            #    i = 0
            imbalance = max([imbalance, i])

        return imbalance


    def calculate_imbalance(self):

        # First, do all the assigned IPs.
        assigned = sorted([ip
                           for n in self.nodes
                           for ip in n.current_addresses])

        i = self.imbalance_for_ips(assigned)

        ig = []
        # FIXME?  If dealing with IP groups, assume the nodes are all
        # the same.
        for ips in self.nodes[0].ip_groups:
            gi = self.imbalance_for_ips(ips)
            ig.append(gi)

        return (i, ig)


    def diff(self):
        """Calculate differences in IP assignments between self and prev.

        Gratuitous IP moves (from a healthy node to a healthy node)
        are prefixed by !!."""

        ip_moves = 0
        grat_ip_moves = 0
        details = []

        for (new, n) in enumerate(self.nodes):
            for ip in n.current_addresses:
                old = self.prev.find_pnn_with_ip(ip)
                if old != new:
                    ip_moves += 1
                    if old != -1 and \
                            self.prev.nodes[new].healthy and \
                            self.nodes[new].healthy and \
                            self.nodes[old].healthy and \
                            self.prev.nodes[old].healthy:
                        prefix = "!!"
                        grat_ip_moves += 1
                    else:
                        prefix = "  "
                    details.append("%s %s: %d -> %d" %
                                   (prefix, ip, old, new))

        return (ip_moves, grat_ip_moves, details)

    def find_takeover_node(self, ip):

        pnn = -1
        min = 0
        for (i, n) in enumerate(self.nodes):
            if not n.healthy:
                continue

            if not n.can_node_serve_ip(ip):
                continue

            num = n.node_ip_coverage()

            if (pnn == -1):
                pnn = i
                min = num
            else:
                if num < min:
                    pnn = i
                    min = num

        if pnn == -1:
            verbose_print("Could not find node to take over public address %s" % ip)
            return False

        self.nodes[pnn].current_addresses.add(ip)

        verbose_print("%s -> %d" % (ip, pnn))
        return True

    def basic_allocate_unassigned(self):

        assigned = set([ip for n in self.nodes for ip in n.current_addresses])
        unassigned = sorted(list(self.all_public_ips - assigned))

        for ip in unassigned:
            self.find_takeover_node(ip)

    def basic_failback(self, retries_l):

        assigned = sorted([ip
                           for n in self.nodes
                           for ip in n.current_addresses])
        for ip in assigned:

            maxnode = -1
            minnode = -1
            for (i, n) in enumerate(self.nodes):
                if not n.healthy:
                    continue

                if not n.can_node_serve_ip(ip):
                    continue

                num = n.node_ip_coverage()

                if maxnode == -1:
                    maxnode = i
                    maxnum = num
                else:
                    if num > maxnum:
                        maxnode = i
                        maxnum = num
                if minnode == -1:
                    minnode = i
                    minnum = num
                else:
                    if num < minnum:
                        minnode = i
                        minnum = num

            if maxnode == -1:
                print "Could not find maxnode. May not be able to serve ip", ip
                continue

            #if self.deterministic_public_ips:
            #    continue

            if maxnum > minnum + 1 and retries_l[0] < options.retries:
                # Remove the 1st ip from maxnode
                t = sorted(list(self.nodes[maxnode].current_addresses))
                realloc = t[0]
                verbose_print("%s <- %d" % (realloc, maxnode))
                self.nodes[maxnode].current_addresses.remove(realloc)
                # Redo the outer loop.
                retries_l[0] += 1
                return True

        return False


    def lcp2_allocate_unassigned(self):

        # Assign as many unassigned addresses as possible.  Keep
        # selecting the optimal assignment until we don't manage to
        # assign anything.
        assigned = set([ip for n in self.nodes for ip in n.current_addresses])
        unassigned = sorted(list(self.all_public_ips - assigned))

        should_loop = True
        while len(unassigned) > 0 and should_loop:
            should_loop = False

            debug_begin(" CONSIDERING MOVES (UNASSIGNED)")

            minnode = -1
            mindsum = 0
            minip = None

            for ip in unassigned:
                for dstnode in range(len(self.nodes)):
                    if self.nodes[dstnode].can_node_serve_ip(ip) and \
                            self.nodes[dstnode].healthy:
                        dstdsum = ip_distance_2_sum(ip, self.nodes[dstnode].current_addresses)
                        dstimbl = self.nodes[dstnode].get_imbalance() + dstdsum
                        debug_print(" %s -> %d [+%d]" % \
                                        (ip,
                                         dstnode,
                                         dstimbl - self.nodes[dstnode].get_imbalance()))

                        if (minnode == -1) or (dstdsum < mindsum):
                            minnode = dstnode
                            minimbl = dstimbl
                            mindsum = dstdsum
                            minip = ip
                            should_loop = True
            debug_end()

            if minnode != -1:
                self.nodes[minnode].current_addresses.add(minip)
                self.nodes[minnode].set_imbalance(self.nodes[minnode].get_imbalance() + mindsum)
                verbose_print("%s -> %d [+%d]" % (minip, minnode, mindsum))
                unassigned.remove(minip)

        for ip in unassigned:
            verbose_print("Could not find node to take over public address %s" % ip)

    def lcp2_failback(self, targets):

        # Get the node with the highest imbalance metric.
        srcnode = -1
        maximbl = 0
        for (pnn, n) in enumerate(self.nodes):
            b = n.get_imbalance()
            if (srcnode == -1) or (b > maximbl):
                srcnode = pnn
                maximbl = b

        # This means that all nodes had 0 or 1 addresses, so can't
        # be imbalanced.
        if maximbl == 0:
            return False

        # We'll need this a few times...
        ips = self.nodes[srcnode].current_addresses

        # Find an IP and destination node that best reduces imbalance.
        optimum = None
        debug_begin(" CONSIDERING MOVES FROM %d [%d]" % (srcnode, maximbl))
        for ip in ips:
            # What is this IP address costing the source node?
            srcdsum = ip_distance_2_sum(ip, ips - set([ip]))
            srcimbl = maximbl - srcdsum

            # Consider this IP address would cost each potential
            # destination node.  Destination nodes are limited to
            # those that are newly healthy, since we don't want to
            # do gratuitous failover of IPs just to make minor
            # balance improvements.
            for dstnode in targets:
                if self.nodes[dstnode].can_node_serve_ip(ip) and \
                        self.nodes[dstnode].healthy:
                    dstdsum = ip_distance_2_sum(ip, self.nodes[dstnode].current_addresses)
                    dstimbl = self.nodes[dstnode].get_imbalance() + dstdsum
                    debug_print(" %d [%d] -> %s -> %d [+%d]" % \
                                    (srcnode,
                                     srcimbl - self.nodes[srcnode].get_imbalance(),
                                     ip,
                                     dstnode,
                                     dstimbl - self.nodes[dstnode].get_imbalance()))

                    if (dstimbl < maximbl) and (dstdsum < srcdsum):
                        if optimum is None:
                            optimum = (ip, srcnode, srcimbl, dstnode, dstimbl)
                        else:
                            (x, sn, si, dn, di) = optimum
                            if (srcimbl + dstimbl) < (si + di):
                                optimum = (ip, srcnode, srcimbl, dstnode, dstimbl)
        debug_end()

        if optimum is not None:
            # We found a move that makes things better...
            (ip, srcnode, srcimbl, dstnode, dstimbl) = optimum
            ini_srcimbl = self.nodes[srcnode].get_imbalance()
            ini_dstimbl = self.nodes[dstnode].get_imbalance()

            self.nodes[srcnode].current_addresses.remove(ip)
            self.nodes[srcnode].set_imbalance(srcimbl)

            self.nodes[dstnode].current_addresses.add(ip)
            self.nodes[dstnode].set_imbalance(dstimbl)

            verbose_print("%d [%d] -> %s -> %d [+%d]" % \
                              (srcnode,
                               srcimbl - ini_srcimbl,
                               ip,
                               dstnode,
                               dstimbl - ini_dstimbl))

            return True

        return False

    def ctdb_takeover_run_python(self):

        # Don't bother with the num_healthy stuff.  It is an
        # irrelevant detail.

        # We just keep the allocate IPs in the current_addresses field
        # of the node.  This needs to readable, not efficient!

        if self.deterministic_public_ips:
            # Remap everything.
            addr_list = sorted(list(self.all_public_ips))
            for (i, ip) in enumerate(addr_list):
                self.quietly_remove_ip(ip)
                # Add addresses to new node.
                pnn = i % len(self.nodes)
                self.nodes[pnn].current_addresses.add(ip)
                verbose_print("%s -> %d" % (ip, pnn))

        # Remove public addresses from unhealthy nodes.
        for (pnn, n) in enumerate(self.nodes):
            if not n.healthy:
                verbose_print(["%s <- %d" % (ip, pnn)
                               for ip in n.current_addresses])
                n.current_addresses = set()

        # If a node can't serve an assigned address then remove it.
        for n in self.nodes:
            verbose_print(["%s <- %d" % (ip, pnn)
                           for ip in n.current_addresses - n.public_addresses])
            n.current_addresses &= n.public_addresses

        if options.lcp2:
            newly_healthy = [pnn for (pnn, n) in enumerate(self.nodes)
                             if len(n.current_addresses) == 0 and n.healthy]
            for n in self.nodes:
                n.set_imbalance()

        # We'll only retry the balancing act up to options.retries
        # times (for the basic non-deterministic algorithm).  This
        # nonsense gives us a reference on the retries count in
        # Python.  It will be easier in C.  :-)
        # For LCP2 we reassignas many IPs from heavily "loaded" nodes
        # to nodes that are newly healthy, looping until we fail to
        # reassign an IP.
        retries_l = [0]
        should_loop = True
        while should_loop:
            should_loop = False

            if options.lcp2:
                self.lcp2_allocate_unassigned()
            else:
                self.basic_allocate_unassigned()

            if self.no_ip_failback or self.deterministic_public_ips:
                break

            if options.lcp2:
                if len(newly_healthy) == 0:
                    break
                should_loop = self.lcp2_failback(newly_healthy)
            else:
                should_loop = self.basic_failback(retries_l)

    def ctdb_takeover_run_external(self):

        # Written while asleep...

        # Convert the cluster state to something that be fed to
        # ctdb_takeover_tests ctdb_takeover_run_core ...

        in_lines = []
        for ip in sorted(list(self.all_public_ips)):
            allowed = []
            assigned = -1
            for (i, n) in enumerate(self.nodes):
                if n.can_node_serve_ip(ip):
                    allowed.append("%s" % i)
                if ip in n.current_addresses:
                    assigned = i
            line = "%s\t%d\t%s" % (ip, assigned, ",".join(allowed))
            in_lines.append(line)

        nodestates = ",".join(["0" if n.healthy else "1" for n in self.nodes])

        if options.lcp2:
            os.environ["CTDB_LCP2"] = "yes"
        if options.verbose > 1:
            os.environ["CTDB_TEST_LOGLEVEL"] = "4"
        elif options.verbose == 1:
            os.environ["CTDB_TEST_LOGLEVEL"] = "3"
        else:
            os.environ["CTDB_TEST_LOGLEVEL"] = "0"

        p = subprocess.Popen("../../bin/ctdb_takeover_tests ctdb_takeover_run_core %s 2>&1" % nodestates,
                             shell=True,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write("\n".join(in_lines))
        p.stdin.close()

        # Flush all of the assigned IPs.
        for n in self.nodes:
            n.current_addresses = set()

        # Uses the results to populate the current_addresses for each
        # node.
        for line in p.stdout.read().split("\n"):
            # Some lines are debug, some are the final IP
            # configuration.  Let's use a gross hack that assumes any
            # line with 2 words is IP configuration.  That will do for
            # now.
            words = re.split("\s+", line)
            if len(words) == 2:
                # Add the IP as current for the specified node.
                self.nodes[int(words[1])].current_addresses.add(words[0])
            else:
                 # First 3 words are log date/time, remove them...
                 print " ".join(words[3:])

        # Now fake up the LCP calculations.
        for n in self.nodes:
            n.set_imbalance()

    def ctdb_takeover_run(self):

        self.events += 1

        if options.external:
            return self.ctdb_takeover_run_external()
        else:
            return self.ctdb_takeover_run_python()

    def recover(self):
        verbose_begin("TAKEOVER")

        self.ctdb_takeover_run()

        verbose_end()

        grat_ip_moves = 0

        if self.prev is not None:
            (ip_moves, grat_ip_moves, details) = self.diff()
            self.ip_moves.append(ip_moves)
            self.grat_ip_moves.append(grat_ip_moves)

            if options.diff:
                print_begin("DIFF")
                print "\n".join(details)
                print_end()

        (imbalance, imbalance_groups) = self.calculate_imbalance()
        self.imbalance.append(imbalance)
        self.imbalance_groups.append(imbalance_groups)

        if imbalance > options.soft_limit:
            self.imbalance_count += 1

        # There must be a cleaner way...
        t = []
        for (c, i) in zip(self.imbalance_groups_count, imbalance_groups):
            if i > options.soft_limit:
                t.append(c + i)
            else:
                t.append(c)
        self.imbalance_groups_count = t

        imbalance_metric = max([n.get_imbalance() for n in self.nodes])
        self.imbalance_metric.append(imbalance_metric)
        if options.balance:
            print_begin("IMBALANCE")
            print "ALL IPS:", imbalance
            if self.have_ip_groups():
                print "IP GROUPS:", imbalance_groups
            if options.lcp2:
                print "LCP2 IMBALANCE:", imbalance_metric
            print_end()

        num_unhealthy = len(self.nodes) - \
            len([n for n in self.nodes if n.healthy])
        self.num_unhealthy.append(num_unhealthy)

        if options.show:
            print_begin("STATE")
            print self
            print_end()

        self.prev = None
        self.prev = copy.deepcopy(self)

        # True is bad!
        return (grat_ip_moves > 0) or \
            (not self.have_ip_groups() and imbalance > options.hard_limit) or \
            (self.have_ip_groups() and (max(imbalance_groups) > options.hard_limit))
