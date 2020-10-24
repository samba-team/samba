# Samba wrapper for DNS resolvers
#
# Copyright (C) Stanislav Levin <slev@altlinux.org>
# Copyright (C) Alexander Bokovoy <ab@samba.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import dns.resolver
import dns.rdatatype
import dns.reversename

class DNSResolver(dns.resolver.Resolver):
    """DNS stub resolver compatible with both dnspython < 2.0.0
    and dnspython >= 2.0.0.

    Set `use_search_by_default` attribute to `True`, which
    determines the default for whether the search list configured
    in the system's resolver configuration is used for relative
    names, and whether the resolver's domain may be added to relative
    names.

    Increase the default lifetime which determines the number of seconds
    to spend trying to get an answer to the question. dnspython 2.0.0
    changes this to 5sec, while the previous one was 30sec.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reset_defaults()
        self.resolve = getattr(super(), "resolve", self.query)
        self.resolve_address = getattr(
            super(),
            "resolve_address",
            self._resolve_address
        )

    def reset_defaults(self):
        self.use_search_by_default = True
        # the default is 5sec
        self.lifetime = 15

    def reset(self):
        super().reset()
        self.reset_defaults()

    def _resolve_address(self, ip_address, *args, **kwargs):
        """Query nameservers for PTR records.

        :param ip_address: IPv4 or IPv6 address
        :type ip_address: str
        """
        return self.resolve(
            dns.reversename.from_address(ip_address),
            rdtype=dns.rdatatype.PTR,
            *args,
            **kwargs,
        )
