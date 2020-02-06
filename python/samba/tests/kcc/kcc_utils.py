# Unix SMB/CIFS implementation. Tests for samba.kcc.kcc_utils.
# Copyright (C) Andrew Bartlett 2015
#
# Written by Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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

"""Tests for samba.kcc.kcc_utils"""
import samba
import samba.tests
from samba.kcc.kcc_utils import new_connection_schedule, drsblobs
from samba.kcc.kcc_utils import uncovered_sites_to_cover
from samba.credentials import Credentials
from samba.auth import system_session
from samba.samdb import SamDB
from samba.tests import delete_force


class ScheduleTests(samba.tests.TestCase):

    def test_new_connection_schedule(self):
        schedule = new_connection_schedule()
        self.assertIsInstance(schedule, drsblobs.schedule)
        self.assertEqual(schedule.size, 188)
        self.assertEqual(len(schedule.dataArray[0].slots), 168)


# OK, this is pathetic, but the rest of it looks really hard, with the
# classes all intertwingled with each other and the samdb. That is to say:
# XXX later.

class SiteCoverageTests(samba.tests.TestCase):

    def setUp(self):
        self.prefix = "kcc_"
        self.lp = samba.tests.env_loadparm()

        self.sites = {}
        self.site_links = {}

        self.creds = Credentials()
        self.creds.guess(self.lp)
        self.session = system_session()

        self.samdb = SamDB(session_info=self.session,
                           credentials=self.creds,
                           lp=self.lp)

    def tearDown(self):
        self.samdb.transaction_start()

        for site in self.sites:
            delete_force(self.samdb, site, controls=['tree_delete:1'])

        for site_link in self.site_links:
            delete_force(self.samdb, site_link)

        self.samdb.transaction_commit()

    def _add_server(self, name, site):
        dn = "CN={0},CN=Servers,{1}".format(name, site)
        self.samdb.add({
            "dn": dn,
            "objectClass": "server",
            "serverReference": self.samdb.domain_dn()
        })
        return dn

    def _add_site(self, name):
        dn = "CN={0},CN=Sites,{1}".format(
            name, self.samdb.get_config_basedn()
        )
        self.samdb.add({
            "dn": dn,
            "objectClass": "site"
        })
        self.samdb.add({
            "dn": "CN=Servers," + dn,
            "objectClass": ["serversContainer"]
        })

        self.sites[dn] = name
        return dn, name.lower()

    def _add_site_link(self, name, links=[], cost=100):
        dn = "CN={0},CN=IP,CN=Inter-Site Transports,CN=Sites,{1}".format(
            name, self.samdb.get_config_basedn()
        )
        self.samdb.add({
            "dn": dn,
            "objectClass": "siteLink",
            "cost": str(cost),
            "siteList": links
        })
        self.site_links[dn] = name
        return dn

    def test_single_site_link_same_dc_count(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)

        self._add_site_link(self.prefix + "link",
                            [site1, site2, uncovered_dn])
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([], to_cover)

    def test_single_site_link_different_dc_count(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "ABCD" + '2', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "BCDE" + '2', site2)
        self._add_server(self.prefix + "BCDE" + '3', site2)

        self._add_site_link(self.prefix + "link",
                            [site1, site2, uncovered_dn])
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

    def test_two_site_links_same_cost(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "ABCD" + '2', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "BCDE" + '2', site2)
        self._add_server(self.prefix + "BCDE" + '3', site2)

        self._add_site_link(self.prefix + "link1",
                            [site1, uncovered_dn])
        self._add_site_link(self.prefix + "link2",
                            [site2, uncovered_dn])
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

    def test_two_site_links_different_costs(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "BCDE" + '2', site2)

        self._add_site_link(self.prefix + "link1",
                            [site1, uncovered_dn],
                            cost=50)
        self._add_site_link(self.prefix + "link2",
                            [site2, uncovered_dn],
                            cost=75)
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([], to_cover)

    def test_three_site_links_different_costs(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")
        site3, name3 = self._add_site(self.prefix + "CDEF")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "CDEF" + '1', site3)
        self._add_server(self.prefix + "CDEF" + '2', site3)

        self._add_site_link(self.prefix + "link1",
                            [site1, uncovered_dn],
                            cost=50)
        self._add_site_link(self.prefix + "link2",
                            [site2, uncovered_dn],
                            cost=75)
        self._add_site_link(self.prefix + "link3",
                            [site3, uncovered_dn],
                            cost=60)
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name3)
        to_cover.sort()

        self.assertEqual([], to_cover)

    def test_three_site_links_duplicate_costs(self):
        # two of the links have the same cost; the other is higher
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")
        site3, name3 = self._add_site(self.prefix + "CDEF")

        uncovered_dn, uncovered = self._add_site(self.prefix + "uncovered")

        self._add_server(self.prefix + "ABCD" + '1', site1)
        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "CDEF" + '1', site3)
        self._add_server(self.prefix + "CDEF" + '2', site3)

        self._add_site_link(self.prefix + "link1",
                            [site1, uncovered_dn],
                            cost=50)
        self._add_site_link(self.prefix + "link2",
                            [site2, uncovered_dn],
                            cost=75)
        self._add_site_link(self.prefix + "link3",
                            [site3, uncovered_dn],
                            cost=50)
        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name3)
        to_cover.sort()

        self.assertEqual([uncovered], to_cover)

    def test_complex_setup_with_multiple_uncovered_sites(self):
        self.samdb.transaction_start()
        site1, name1 = self._add_site(self.prefix + "ABCD")
        site2, name2 = self._add_site(self.prefix + "BCDE")
        site3, name3 = self._add_site(self.prefix + "CDEF")

        site4, name4 = self._add_site(self.prefix + "1234")
        site5, name5 = self._add_site(self.prefix + "2345")
        site6, name6 = self._add_site(self.prefix + "3456")

        uncovered_dn1, uncovered1 = self._add_site(self.prefix + "uncovered1")
        uncovered_dn2, uncovered2 = self._add_site(self.prefix + "uncovered2")
        uncovered_dn3, uncovered3 = self._add_site(self.prefix + "uncovered3")

        # Site Link Cluster 1 - Server List
        self._add_server(self.prefix + "ABCD" + '1', site1)

        self._add_server(self.prefix + "BCDE" + '1', site2)
        self._add_server(self.prefix + "BCDE" + '2', site2)

        self._add_server(self.prefix + "CDEF" + '1', site3)
        self._add_server(self.prefix + "CDEF" + '2', site3)
        self._add_server(self.prefix + "CDEF" + '3', site3)

        # Site Link Cluster 2 - Server List
        self._add_server(self.prefix + "1234" + '1', site4)
        self._add_server(self.prefix + "1234" + '2', site4)

        self._add_server(self.prefix + "2345" + '1', site5)
        self._add_server(self.prefix + "2345" + '2', site5)

        self._add_server(self.prefix + "3456" + '1', site6)

        # Join to Uncovered1 (preference to site link cluster 1)
        self._add_site_link(self.prefix + "link1A",
                            [site1, site2, site3, uncovered_dn1],
                            cost=49)
        self._add_site_link(self.prefix + "link2A",
                            [site4, site5, site6, uncovered_dn1],
                            cost=50)

        # Join to Uncovered2 (no preferene on site links)
        self._add_site_link(self.prefix + "link1B",
                            [site1, site2, site3, uncovered_dn2],
                            cost=50)
        self._add_site_link(self.prefix + "link2B",
                            [site4, site5, site6, uncovered_dn2],
                            cost=50)

        # Join to Uncovered3 (preference to site link cluster 2)
        self._add_site_link(self.prefix + "link1C",
                            [site1, site2, site3, uncovered_dn3],
                            cost=50)
        self._add_site_link(self.prefix + "link2C",
                            [site4, site5, site6, uncovered_dn3],
                            cost=49)

        self.samdb.transaction_commit()

        to_cover = uncovered_sites_to_cover(self.samdb, name1)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name2)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name3)
        to_cover.sort()

        self.assertEqual([uncovered1, uncovered2], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name4)
        to_cover.sort()

        self.assertEqual([uncovered2, uncovered3], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name5)
        to_cover.sort()

        self.assertEqual([], to_cover)

        to_cover = uncovered_sites_to_cover(self.samdb, name6)
        to_cover.sort()

        self.assertEqual([], to_cover)

        for to_check in [uncovered1, uncovered2, uncovered3]:
            to_cover = uncovered_sites_to_cover(self.samdb, to_check)
            to_cover.sort()

            self.assertEqual([], to_cover)
