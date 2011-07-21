#!/usr/bin/env python

# ctdb ip takeover code

# Copyright (C) Martin Schwenke 2010

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
    parser.add_option("--hack",
                      action="store", type="int", dest="hack", default=0,
                      help="apply a hack (see the code!!!)")
    parser.add_option("-r", "--retries",
                      action="store", type="int", dest="retries", default=5,
                      help="number of retry loops for rebalancing [default: %default]")
    parser.add_option("-i", "--iterations",
                      action="store", type="int", dest="iterations",
                      default=1000,
                      help="number of iterations to run in test [default: %default]")
    parser.add_option("-o", "--odds",
                      action="store", type="int", dest="odds", default=4,
                      help="make the chances of a failover 1 in ODDS [default: %default]")

    def seed_callback(option, opt, value, parser):
        random.seed(value)
    parser.add_option("-s", "--seed",
                      action="callback", type="int", callback=seed_callback,
                      help="initial random number seed for random events")

    parser.add_option("-x", "--exit",
                      action="store_true", dest="exit", default=False,
                      help="exit on the 1st gratuitous IP move")
    
    (options, args) = parser.parse_args()

    if len(args) != 0:
        parser.error("too many argumentss")

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


class Node(object):
    def __init__(self, public_addresses):
        self.public_addresses = set(public_addresses)
        self.current_addresses = set()
        self.healthy = True

    def can_node_serve_ip(self, ip):
        return ip in self.public_addresses

    def node_ip_coverage(self):
        return len(self.current_addresses)

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
        self.events = -1
        self.num_unhealthy = []

        self.prev = None

    def __str__(self):
        return "\n".join(["%2d %s %s" %
                          (i,
                           "*" if len(n.public_addresses) == 0 else \
                               (" " if n.healthy else "#"),
                           sorted(list(n.current_addresses)))
                          for (i, n) in enumerate(self.nodes)])

    def print_statistics(self):
        print_begin("STATISTICS")
        print "Events:              %6d" % self.events
        print "Total IP moves:      %6d" % sum(self.ip_moves)
        print "Gratuitous IP moves: %6d" % sum(self.grat_ip_moves)
        print "Max imbalance:       %6d" % max(self.imbalance)
        print "Final imbalance:     %6d" % self.imbalance[-1]
        print "Maximum unhealthy:   %6d" % max(self.num_unhealthy)
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


        """Make a random node healthy or unhealthy.

        If all nodes are healthy or unhealthy, then invert one of
        them.  Otherwise, there's a 1 in options.odds chance of making
        another node unhealthy."""

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

    def random_iterations(self):
        i = 1
        while i <= options.iterations:
            verbose_begin("EVENT %d" % i)
            verbose_end()
            self.do_something_random()
            if self.recover() and options.exit > 0:
                break
            i += 1

        self.print_statistics()

    def calculate_imbalance(self):

        imbalance = 0

        assigned = sorted([ip
                           for n in self.nodes
                           for ip in n.current_addresses])

        for ip in assigned:

            num_capable = 0
            maxnode = -1
            minnode = -1
            for (i, n) in enumerate(self.nodes):
                if not n.healthy:
                    continue

                if not n.can_node_serve_ip(ip):
                    continue

                num_capable += 1

                num = n.node_ip_coverage()

                if maxnode == -1 or num > maxnum:
                    maxnode = i
                    maxnum = num

                if minnode == -1 or num < minnum:
                    minnode = i
                    minnum = num
            
            if maxnode == -1:
                continue

            i = maxnum - minnum
            if maxnum - minnum < 2:
                i = 0
            imbalance = max([imbalance, i])

        return imbalance

    def diff(self):
        """Calculate differences in IP assignments between self and prev.

        Gratuitous IP moves (from a healthy node to a healthy node)
        are prefix by !!.  Any gratuitous IP moves cause this function
        to return False.  If there are no gratuitous moves then it
        will return True."""

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
                    
    def find_least_loaded_node(self, ip):
        """Just like find_takeover_node but doesn't care about health."""
        pnn = -1
        min = 0
        for (i, n) in enumerate(self.nodes):
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

    def ctdb_takeover_run(self):

        self.events += 1

        # Don't bother with the num_healthy stuff.  It is an
        # irrelevant detail.

        # We just keep the allocate IPs in the current_addresses field
        # of the node.  This needs to readable, not efficient!

        if self.deterministic_public_ips:
            # Remap everything.
            addr_list = sorted(list(self.all_public_ips))
            for (i, ip) in enumerate(addr_list):
                if options.hack == 1:
                    self.quietly_remove_ip(ip)
                    self.find_least_loaded_node(ip)
                elif options.hack == 2:
                    pnn = i % len(self.nodes)
                    if ip in self.nodes[pnn].public_addresses:
                        self.quietly_remove_ip(ip)
                        # Add addresses to new node.
                        self.nodes[pnn].current_addresses.add(ip)
                        verbose_print("%s -> %d" % (ip, pnn))
                else:
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

        # We'll only retry the balancing act up to 5 times.
        retries = 0
        should_loop = True
        while should_loop:
            should_loop = False

            assigned = set([ip for n in self.nodes for ip in n.current_addresses])
            unassigned = sorted(list(self.all_public_ips - assigned))

            for ip in unassigned:
                self.find_takeover_node(ip)

            if self.no_ip_failback:
                break

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
                    print "Could not maxnode. May not be able to serve ip", ip
                    continue

                if self.deterministic_public_ips:
                    continue

                if maxnum > minnum + 1 and retries < options.retries:
                    # Remove the 1st ip from maxnode
                    t = sorted(list(self.nodes[maxnode].current_addresses))
                    realloc = t[0]
                    verbose_print("%s <- %d" % (realloc, maxnode))
                    self.nodes[maxnode].current_addresses.remove(realloc)
                    retries += 1
                    # Redo the outer loop.
                    should_loop = True
                    break

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

        imbalance = self.calculate_imbalance()
        self.imbalance.append(imbalance)
        if options.balance:
            print_begin("IMBALANCE")
            print imbalance
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

        return grat_ip_moves
