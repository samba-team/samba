# Unix SMB/CIFS implementation.
# Copyright Volker Lendecke <vl@samba.org> 2022
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

import os
import shutil
import struct
from samba.samba3 import libsmb_samba_internal as libsmb
from samba import reparse_symlink
from samba import (ntstatus,NTSTATUSError)
from samba.dcerpc import security as sec
import samba.tests.libsmb

class Smb2SymlinkTests(samba.tests.libsmb.LibsmbTests):

    def connections(self, smb1share=None, smb2share=None):
        if not smb1share:
            smb1share = samba.tests.env_get_var_value(
                "SMB1_SHARE", allow_missing=True)
            if not smb1share:
                smb1share = self.share_name("nosymlinks_smb1allow")

        try:
            smb1 = libsmb.Conn(
                self.server_ip,
                smb1share,
                self.lp,
                self.creds,
                force_smb1=True)
        except NTSTATUSError as e:
            if e.args[0] != ntstatus.NT_STATUS_CONNECTION_RESET:
                raise
        smb1.smb1_posix()

        if not smb2share:
            smb2share = samba.tests.env_get_var_value(
                "SMB2_SHARE", allow_missing=True)
            if not smb2share:
                smb2share = self.share_name("nosymlinks")

        smb2 = libsmb.Conn(
            self.server_ip,
            smb2share,
            self.lp,
            self.creds)
        return (smb1, smb2)

    def create_symlink(self, conn, target, symlink, directory=False):

        self.clean_file(conn, symlink)
        if (conn.protocol() < libsmb.PROTOCOL_SMB2_02 and
            conn.have_posix()):
            conn.smb1_symlink(target, symlink)
        else:
            flags = 0 if target[0]=='/' else 1
            # NTFS needs a directory symlink to be created as a
            # directory, there is no SMB1 POSIX-like symlink call
            if directory:
                attrs = libsmb.FILE_ATTRIBUTE_DIRECTORY
                opts = (libsmb.FILE_DIRECTORY_FILE |
                        libsmb.FILE_OPEN_REPARSE_POINT)
            else:
                attrs = libsmb.FILE_ATTRIBUTE_NORMAL
                opts = libsmb.FILE_OPEN_REPARSE_POINT
            syml = conn.create(
                symlink,
                DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE|
                sec.SEC_FILE_WRITE_ATTRIBUTE|
                sec.SEC_STD_DELETE,
                FileAttributes=attrs,
                CreateDisposition=libsmb.FILE_OPEN_IF,
                CreateOptions=opts)
            b = reparse_symlink.symlink_put(target, target, 0, 1)
            conn.fsctl(syml, libsmb.FSCTL_SET_REPARSE_POINT, b, 0)
            conn.close(syml)

    def verify_symlink(self, conn, symlink, expect_tgt):
        """Check via SMB2 that symlink is a symlink to expect_tgt"""
        fd = conn.create(symlink,
                         DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
                         CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT,
                         CreateDisposition=libsmb.FILE_OPEN)
        blob = conn.fsctl(fd, libsmb.FSCTL_GET_REPARSE_POINT, b'', 1024)
        conn.close(fd)

        (tag,(subst,_,_,_)) = reparse_symlink.get(blob)
        self.assertEqual(tag, "IO_REPARSE_TAG_SYMLINK")
        self.assertEqual(expect_tgt, subst)

    def assert_symlink_exception(self, e, expect):
        self.assertEqual(e.args[0], ntstatus.NT_STATUS_STOPPED_ON_SYMLINK)
        for k,v in expect.items():
            if (k == "flags"):
                # Ignore symlink trust flags for now
                expected = v & ~libsmb.SYMLINK_TRUST_MASK
                got = e.args[2].get(k) & ~libsmb.SYMLINK_TRUST_MASK
                self.assertEqual((k,got), (k,expected))
            else:
                self.assertEqual((k,e.args[2].get(k)), (k,v))

    def test_symlinkerror_directory(self):
        """Test a symlink in a nonterminal path component"""
        (smb1,smb2) = self.connections()
        symlink="syml"
        target="foo"
        suffix="bar"

        self.create_symlink(smb1, target, symlink)
        self.verify_symlink(smb2, symlink, target)

        with self.assertRaises(NTSTATUSError) as e:
            fd = smb2.create_ex(f'{symlink}\\{suffix}')

        self.assert_symlink_exception(
            e.exception,
            { 'unparsed_path_length' : len(suffix)+1,
              'substitute_name' : target,
              'print_name' : target,
              'flags' : 0x20000001 })

        self.clean_file(smb1, symlink)

    def test_symlinkerror_file(self):
        """Test a simple symlink in a terminal path"""
        (smb1,smb2) = self.connections()
        symlink="syml"
        target="foo"

        self.create_symlink(smb1, target, symlink)
        self.verify_symlink(smb2, symlink, target)

        with self.assertRaises(NTSTATUSError) as e:
            fd = smb2.create_ex(f'{symlink}')

        self.assert_symlink_exception(
                e.exception,
            { 'unparsed_path_length' : 0,
              'substitute_name' : target,
              'print_name' : target,
              'flags' : 0x20000001 })

        self.clean_file(smb1, symlink)

    def test_symlinkerror_absolute_outside_share(self):
        """
        Test symlinks to outside of the share
        We return the contents 1:1
        """
        (smb1,smb2) = self.connections()
        symlink="syml"

        for target in ["/etc", "//foo/bar", "/"]:

            self.create_symlink(smb1, target, symlink)
            self.verify_symlink(smb2, symlink, target)

            with self.assertRaises(NTSTATUSError) as e:
                fd = smb2.create_ex(f'{symlink}')

            self.assert_symlink_exception(
                e.exception,
                { 'unparsed_path_length' : 0,
                  'substitute_name' : target,
                  'print_name' : target,
                  'flags' : 0 })

            self.clean_file(smb1, symlink)

    def test_symlinkerror_absolute_inshare(self):
        """Test an absolute symlink inside the share"""
        (smb1,smb2) = self.connections()
        symlink="syml"

        localpath=samba.tests.env_get_var_value("LOCAL_PATH")
        shareroot=f'{localpath}/nosymlinks'
        rel_dest="dst"
        target=f'{shareroot}/{rel_dest}'

        self.create_symlink(smb1, target, symlink)
        self.verify_symlink(smb2, symlink, rel_dest)

        with self.assertRaises(NTSTATUSError) as e:
            fd = smb2.create_ex(f'{symlink}')

        self.assert_symlink_exception(
            e.exception,
            { 'unparsed_path_length' : 0,
              'substitute_name' : rel_dest,
              'print_name' : rel_dest,
              'flags' : 1 })

        self.clean_file(smb1, symlink)

    def test_symlink_reparse_data_buffer_parse(self):
        """Test parsing a symlink reparse buffer coming from Windows"""

        buf = (b'\x0c\x00\x00\xa0\x18\x00\x00\x00'
               b'\x06\x00\x06\x00\x00\x00\x06\x00'
               b'\x01\x00\x00\x00\x62\x00\x61\x00'
               b'\x72\x00\x62\x00\x61\x00\x72\x00')

        try:
            (tag,syml) = reparse_symlink.get(buf)
        except:
            self.fail("Could not parse symlink buffer")

        self.assertEqual(tag, "IO_REPARSE_TAG_SYMLINK")
        self.assertEqual(syml, ('bar', 'bar', 0, 1))

    def test_bug15505(self):
        """Test an absolute intermediate symlink inside the share"""
        (smb1, smb2) = self.connections(smb1share=self.share_name("tmp"),
                                        smb2share=self.share_name("tmp"))
        symlink="syml"

        localpath=samba.tests.env_get_var_value("LOCAL_PATH")

        smb1.mkdir("sub")
        self.addCleanup(self.clean_file, smb1, "sub")

        self.create_symlink(smb1, f'{localpath}/sub1', "sub/lnk")
        self.addCleanup(self.clean_file, smb1, "sub/lnk")

        smb1.mkdir("sub1")
        self.addCleanup(self.clean_file, smb1, "sub1")

        fd = smb1.create("sub1/x", CreateDisposition=libsmb.FILE_CREATE);
        smb1.close(fd)
        self.addCleanup(self.clean_file, smb1, "sub1/x")

        fd = smb2.create("sub\\lnk\\x")
        smb2.close(fd)

    def check_follow_symlink_reparse_point(self, smb1share, smb2share,
                                           verify):
        (smb1,smb2) = self.connections(smb1share=smb1share,
                                       smb2share=smb2share)
        symlink="syml"
        target="foo"

        fd = smb2.create(target, CreateDisposition=libsmb.FILE_CREATE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target)

        self.create_symlink(smb1, target, symlink)
        if verify:
            self.verify_symlink(smb2, symlink, target)
        self.addCleanup(self.clean_file, smb1, symlink);

        try:
            fd = smb2.create(symlink,
                             CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        except Exception as e:
            self.fail(f'Could not open file with FILE_OPEN_REPARSE_POINT: {e}')
        smb2.close(fd);

    def test_follow_symlink_reparse_point(self):
        """Open a symlink with FILE_OPEN_REPARSE_POINT, follow symlinks = yes

        The open follows the link, it can't be verified as a symlink.
        """
        self.check_follow_symlink_reparse_point("local_symlinks",
                                                "local_symlinks",
                                                verify=False)

    def test_follow_symlink_reparse_point_nofollow(self):
        """Open a symlink with FILE_OPEN_REPARSE_POINT, follow symlinks = no"""
        self.check_follow_symlink_reparse_point("nosymlinks_smb1allow",
                                                "nosymlinks",
                                                verify=True)

    def test_symlink_reparse_point_share_mode(self):
        """Share modes apply to a symlink opened as reparse point"""
        (smb1,smb2) = self.connections(smb1share="nosymlinks_smb1allow",
                                       smb2share="nosymlinks")
        symlink="syml"
        target="foo"

        fd = smb2.create(target, CreateDisposition=libsmb.FILE_CREATE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target)

        self.create_symlink(smb1, target, symlink)
        self.verify_symlink(smb2, symlink, target)
        self.addCleanup(self.clean_file, smb1, symlink)

        fd = self.assertNoNTSTATUSError(
            smb2.create,
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_DATA,
            ShareAccess=0,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        try:
            fd2 = smb2.create(symlink,
                              DesiredAccess=sec.SEC_FILE_READ_DATA,
                              ShareAccess=(libsmb.FILE_SHARE_READ |
                                           libsmb.FILE_SHARE_WRITE |
                                           libsmb.FILE_SHARE_DELETE),
                              CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        except NTSTATUSError as e:
            self.assertEqual(e.args[0], ntstatus.NT_STATUS_SHARING_VIOLATION)
        else:
            smb2.close(fd2)
            self.fail("Second open ignored ShareAccess=0 of the first")

    def symlink_conn(self, share):
        """Connection to create real symlinks with

        SMB1 POSIX by default. Windows has no SMB1 POSIX
        extensions, there set SYMLINK_VIA_FSCTL=1 to create them
        with FSCTL_SET_REPARSE_POINT over SMB2.
        """
        via_fsctl = samba.tests.env_get_var_value(
            "SYMLINK_VIA_FSCTL", allow_missing=True)
        if via_fsctl:
            return libsmb.Conn(self.server_ip, share, self.lp, self.creds)

        conn = libsmb.Conn(
            self.server_ip, share, self.lp, self.creds, force_smb1=True)
        conn.smb1_posix()
        return conn

    def test_symlink_reparse_point_empty(self):
        """Test that a symlink opened as reparse point has no data"""
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        if share:
            # Against Windows both are the same share
            smb1share = share
            smb2share = share
        else:
            smb1share = self.share_name("nosymlinks_smb1allow")
            smb2share = self.share_name("nosymlinks")
        smb2 = libsmb.Conn(self.server_ip, smb2share, self.lp, self.creds)
        lnkconn = self.symlink_conn(smb1share)
        symlink="syml"
        target="foo"

        fd = smb2.create(target,
                         DesiredAccess=sec.SEC_FILE_WRITE_DATA,
                         CreateDisposition=libsmb.FILE_CREATE)
        smb2.write(fd, b"0123456789", 0)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target)

        self.create_symlink(lnkconn, target, symlink)
        self.verify_symlink(smb2, symlink, target)
        self.addCleanup(self.clean_file, lnkconn, symlink)

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        self.assertEqual(cr['end_of_file'], 0)
        self.assertEqual(cr['allocation_size'], 0)

        info = smb2.qfileinfo(fd, libsmb.FSCC_FILE_STANDARD_INFORMATION)
        self.assertEqual(info['end_of_file'], 0)
        self.assertEqual(info['allocation_size'], 0)

        streams = smb2.qfileinfo(fd, libsmb.FSCC_FILE_STREAM_INFORMATION)
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]['name'], "::$DATA")
        self.assertEqual(streams[0]['size'], 0)
        self.assertEqual(streams[0]['allocation_size'], 0)

        # cli_read() turns NT_STATUS_END_OF_FILE into an empty read
        data = self.assertNoNTSTATUSError(smb2.read, fd, 0, 10)
        self.assertEqual(data, b'')

    def test_symlink_reparse_point_set_size_0(self):
        """Setting the size a symlink opened as reparse point has works"""
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        if share:
            # Against Windows both are the same share
            smb1share = share
            smb2share = share
        else:
            smb1share = self.share_name("nosymlinks_smb1allow")
            smb2share = self.share_name("nosymlinks")
        smb2 = libsmb.Conn(self.server_ip, smb2share, self.lp, self.creds)
        lnkconn = self.symlink_conn(smb1share)
        symlink = "syml"
        target = "foo"

        fd = smb2.create(target,
                         DesiredAccess=sec.SEC_FILE_WRITE_DATA,
                         CreateDisposition=libsmb.FILE_CREATE)
        smb2.write(fd, b"0123456789", 0)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target)

        self.create_symlink(lnkconn, target, symlink)
        self.verify_symlink(smb2, symlink, target)
        self.addCleanup(self.clean_file, lnkconn, symlink)

        fd = self.assertNoNTSTATUSError(
            smb2.create,
            symlink,
            DesiredAccess=sec.SEC_FILE_WRITE_DATA |
            sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        # Both levels are a single little-endian 64-bit size, not
        # worth a pylibsmb wrapper
        zero = struct.pack("<Q", 0)

        self.assertNoNTSTATUSError(smb2.sfileinfo,
                                   fd,
                                   libsmb.SMB2_0_INFO_FILE,
                                   libsmb.FSCC_FILE_END_OF_FILE_INFORMATION,
                                   zero)
        self.assertNoNTSTATUSError(smb2.sfileinfo,
                                   fd,
                                   libsmb.SMB2_0_INFO_FILE,
                                   libsmb.FSCC_FILE_ALLOCATION_INFORMATION,
                                   zero)

        info = smb2.qfileinfo(fd, libsmb.FSCC_FILE_STANDARD_INFORMATION)
        self.assertEqual(info['end_of_file'], 0)
        self.assertEqual(info['allocation_size'], 0)

        # The target is untouched
        fd2 = smb2.create(target, DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE)
        info = smb2.qfileinfo(fd2, libsmb.FSCC_FILE_STANDARD_INFORMATION)
        smb2.close(fd2)
        self.assertEqual(info['end_of_file'], 10)

    def test_symlink_rename_fsctl(self):
        """Renaming a reparse point symlink keeps it a reparse point"""
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        smb1share = share if share else self.share_name(
            "nosymlinks_smb1allow")
        smb2 = libsmb.Conn(
            self.server_ip,
            share if share else self.share_name("nosymlinks"),
            self.lp,
            self.creds)
        smb1 = libsmb.Conn(
            self.server_ip, smb1share, self.lp, self.creds, force_smb1=True)
        symlink = "flnk"
        newname = "flnk_renamed"

        self.create_symlink(smb2, "tfile", symlink)
        self.addCleanup(self.clean_file, smb2, symlink)
        self.addCleanup(self.clean_file, smb2, newname)

        self.assertNoNTSTATUSError(smb1.rename, symlink, newname)

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            newname,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        self.assertEqual(
            cr['file_attributes'] & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
            libsmb.FILE_ATTRIBUTE_REPARSE_POINT)
        self.verify_symlink(smb2, newname, "tfile")

    def dir_symlink_setup(self, fsctl):
        """Create a directory with a file and a symlink to it

        With fsctl=False the link is a real POSIX symlink (SMB1
        POSIX), with fsctl=True a reparse point symlink created
        with FSCTL_SET_REPARSE_POINT over SMB2. Both on a share
        with follow symlinks = no. Returns the SMB2 connection and
        the name of the symlink.
        """
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        via_fsctl = samba.tests.env_get_var_value(
            "SYMLINK_VIA_FSCTL", allow_missing=True)
        if share:
            # Against Windows there are no POSIX symlinks
            if not fsctl:
                self.skipTest("No POSIX symlinks on Windows")
            smb1share = share
        else:
            share = self.share_name("nosymlinks")
            smb1share = self.share_name("nosymlinks_smb1allow")
        smb2 = libsmb.Conn(self.server_ip, share, self.lp, self.creds)
        if fsctl:
            lnkconn = smb2
        else:
            lnkconn = self.symlink_conn(smb1share)
        symlink = "dlnk"
        target = "tdir"

        fd = smb2.create(target,
                         CreateDisposition=libsmb.FILE_CREATE,
                         CreateOptions=libsmb.FILE_DIRECTORY_FILE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target)

        # Make sure removing the directory instead of the link fails
        fd = smb2.create(target + "\\f",
                         CreateDisposition=libsmb.FILE_CREATE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, target + "\\f")

        # NTFS needs a directory symlink to be created as a
        # directory, Samba can only store the reparse point in a
        # regular file
        self.create_symlink(lnkconn, target, symlink,
                            directory=bool(via_fsctl))
        self.verify_symlink(smb2, symlink, target)
        self.addCleanup(self.clean_file, lnkconn, symlink)

        return smb2, symlink

    def check_directory_symlink_attributes(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        # Like NTFS, both attributes
        attrs = cr['file_attributes']
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_DIRECTORY,
                         libsmb.FILE_ATTRIBUTE_DIRECTORY)

    def test_directory_symlink_attributes(self):
        """A POSIX symlink to a directory is a directory reparse point"""
        self.check_directory_symlink_attributes(False)

    def test_directory_symlink_attributes_fsctl(self):
        """A reparse point symlink to a directory is a directory"""
        self.check_directory_symlink_attributes(True)

    def check_directory_symlink_setinfo(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        fd = self.assertNoNTSTATUSError(
            smb2.create,
            symlink,
            DesiredAccess=sec.SEC_FILE_WRITE_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.assertNoNTSTATUSError(
            smb2.sfileinfo,
            fd,
            libsmb.SMB2_0_INFO_FILE,
            libsmb.FSCC_FILE_BASIC_INFORMATION,
            libsmb.basic_info_pack(libsmb.FILE_ATTRIBUTE_HIDDEN))
        smb2.close(fd)

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        # Changing attributes must not lose the reparse point and
        # directory bits. A POSIX symlink has no place to store HIDDEN.
        want = (libsmb.FILE_ATTRIBUTE_REPARSE_POINT |
                libsmb.FILE_ATTRIBUTE_DIRECTORY)
        if fsctl:
            want |= libsmb.FILE_ATTRIBUTE_HIDDEN
        self.assertEqual(cr['file_attributes'] & want, want)

    def test_directory_symlink_setinfo(self):
        """Set info on a POSIX directory symlink keeps DIRECTORY"""
        self.check_directory_symlink_setinfo(False)

    def test_directory_symlink_setinfo_fsctl(self):
        """Set info on a reparse point directory symlink keeps DIRECTORY"""
        self.check_directory_symlink_setinfo(True)

    def check_directory_symlink_follow(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        # Entering a directory symlink without FILE_OPEN_REPARSE_POINT
        # tells the client to follow it, like NTFS does
        with self.assertRaises(NTSTATUSError) as e:
            smb2.create_ex(symlink,
                           DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                           CreateOptions=libsmb.FILE_DIRECTORY_FILE)
        self.assert_symlink_exception(
            e.exception,
            {'unparsed_path_length': 0,
             'substitute_name': "tdir"})

    def test_directory_symlink_follow(self):
        """Directory open of a POSIX directory symlink follows it"""
        self.check_directory_symlink_follow(False)

    def test_directory_symlink_follow_fsctl(self):
        """Directory open of a reparse point directory symlink follows it"""
        self.check_directory_symlink_follow(True)

    def remove_local(self, path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    def test_directory_symlink_twrp(self):
        """A symlink in a snapshot is resolved in that snapshot

        In the live tree "tlnk" points to "tdir", which is a file. In
        the snapshot "tdir" is a directory. Asking for the snapshot
        version of "tlnk" must show a directory reparse point.
        """
        snap = "@GMT-2015.10.31-19.40.30"
        root = os.path.join(
            samba.tests.env_get_var_value("LOCAL_PATH"), "shadow")
        snapdir = os.path.join(root, ".snapshots", snap)

        os.makedirs(snapdir, exist_ok=True)
        self.addCleanup(shutil.rmtree, os.path.join(root, ".snapshots"))
        os.mkdir(os.path.join(snapdir, "tdir"))
        os.symlink("tdir", os.path.join(snapdir, "tlnk"))

        for name in ["tdir", "tlnk"]:
            self.addCleanup(self.remove_local, os.path.join(root, name))
        with open(os.path.join(root, "tdir"), "w"):
            pass
        os.symlink("tdir", os.path.join(root, "tlnk"))

        smb2 = libsmb.Conn(self.server_ip, "shadow_nosymlinks", self.lp,
                           self.creds)

        # The live link points to a file
        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            "tlnk",
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        smb2.close(fd)
        self.assertEqual(cr['file_attributes'] &
                         libsmb.FILE_ATTRIBUTE_DIRECTORY, 0)

        # The link in the snapshot points to a directory
        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            f"{snap}\\tlnk",
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        smb2.close(fd)
        attrs = cr['file_attributes']
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_DIRECTORY,
                         libsmb.FILE_ATTRIBUTE_DIRECTORY)

        # A directory open of the snapshot link opens the link itself
        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            f"{snap}\\tlnk",
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=(libsmb.FILE_DIRECTORY_FILE |
                           libsmb.FILE_OPEN_REPARSE_POINT))
        smb2.close(fd)
        self.assertEqual(cr['file_attributes'] &
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)

    def test_directory_symlink_posix_names(self):
        """Names only valid with POSIX pathnames work for the link and target

        "a:b" would be split into a stream, "x*" is a wildcard.
        """
        root = os.path.join(
            samba.tests.env_get_var_value("LOCAL_PATH"), "nosymlinks")
        tdir = "x*dir"
        lnk = "a:lnk"

        os.mkdir(os.path.join(root, tdir))
        self.addCleanup(os.rmdir, os.path.join(root, tdir))
        os.symlink(tdir, os.path.join(root, lnk))
        self.addCleanup(os.unlink, os.path.join(root, lnk))

        smb2 = libsmb.Conn(self.server_ip, "nosymlinks", self.lp,
                           self.creds, posix=True)
        self.assertTrue(smb2.have_posix())

        wire_mode = libsmb.unix_mode_to_wire(0o644)
        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            lnk,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=(libsmb.FILE_OPEN_REPARSE_POINT |
                           libsmb.FILE_DIRECTORY_FILE),
            CreateContexts=[(libsmb.SMB2_CREATE_TAG_POSIX,
                             wire_mode.to_bytes(4, 'little'))])
        smb2.close(fd)

        # A POSIX open does not get the directory attribute
        attrs = cr['file_attributes']
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_DIRECTORY, 0)

    def test_directory_symlink_rename_fsctl(self):
        """Renaming a reparse point directory symlink keeps its attributes"""
        (smb2, symlink) = self.dir_symlink_setup(True)
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        smb1share = share if share else self.share_name(
            "nosymlinks_smb1allow")
        smb1 = libsmb.Conn(
            self.server_ip, smb1share, self.lp, self.creds, force_smb1=True)
        newname = symlink + "_renamed"
        self.addCleanup(self.clean_file, smb2, newname)

        self.assertNoNTSTATUSError(smb1.rename, symlink, newname)

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            newname,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        want = (libsmb.FILE_ATTRIBUTE_REPARSE_POINT |
                libsmb.FILE_ATTRIBUTE_DIRECTORY)
        self.assertEqual(cr['file_attributes'] & want, want)

    def check_directory_symlink_rmdir(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        # What RemoveDirectory() and "rmdir" do
        (fd, _, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_STD_DELETE |
            sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_DIRECTORY_FILE |
            libsmb.FILE_OPEN_REPARSE_POINT)
        self.assertNoNTSTATUSError(smb2.delete_on_close, fd, 1)
        smb2.close(fd)

        # The link is gone ...
        with self.assertRaises(NTSTATUSError) as cm:
            smb2.create(symlink,
                        DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                        CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.assertEqual(cm.exception.args[0],
                         ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND)

        # ... but the target is not
        fd = self.assertNoNTSTATUSError(smb2.create, "tdir\\f")
        smb2.close(fd)

    def test_directory_symlink_rmdir(self):
        """RemoveDirectory on a POSIX directory symlink removes the link"""
        self.check_directory_symlink_rmdir(False)

    def test_directory_symlink_rmdir_fsctl(self):
        """RemoveDirectory on a reparse point directory symlink"""
        self.check_directory_symlink_rmdir(True)

    def smb1_delete_directory_symlink(self, fsctl, smb1share, rmdir):
        """Delete a directory symlink with SMBunlink or SMBrmdir

        Returns the status of the delete and whether the link and
        the file in the target directory still exist. Against
        Windows set SYMLINK_VIA_FSCTL=1 and SMB2_SHARE, SMB1 has to
        be enabled on the server.
        """
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        # A file symlink would behave differently, see
        # SYMLINK_VIA_FSCTL in dir_symlink_setup()
        (fd, cr, _) = smb2.create_ex(
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        smb2.close(fd)
        self.assertEqual(
            cr['file_attributes'] & libsmb.FILE_ATTRIBUTE_DIRECTORY,
            libsmb.FILE_ATTRIBUTE_DIRECTORY,
            "Not a directory symlink, against Windows set "
            "SYMLINK_VIA_FSCTL=1")

        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        if share:
            smb1share = share
        else:
            smb1share = self.share_name(smb1share)
        smb1 = libsmb.Conn(
            self.server_ip, smb1share, self.lp, self.creds, force_smb1=True)

        status = 0
        try:
            if rmdir:
                smb1.rmdir(symlink)
            else:
                smb1.unlink(symlink)
        except NTSTATUSError as e:
            status = e.args[0]

        link_exists = True
        try:
            fd = smb2.create(symlink,
                             DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                             CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
            smb2.close(fd)
        except NTSTATUSError as e:
            if e.args[0] != ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND:
                raise
            link_exists = False

        target_exists = True
        try:
            fd = smb2.create("tdir\\f")
            smb2.close(fd)
        except NTSTATUSError as e:
            if e.args[0] != ntstatus.NT_STATUS_OBJECT_PATH_NOT_FOUND:
                raise
            target_exists = False

        return (status, link_exists, target_exists)

    def check_directory_symlink_smb1_unlink(self, fsctl, smb1share):
        result = self.smb1_delete_directory_symlink(
            fsctl, smb1share, rmdir=False)
        # Like DeleteFile on NTFS: a directory link is no file
        self.assertEqual(
            result,
            (ntstatus.NT_STATUS_FILE_IS_A_DIRECTORY, True, True),
            "(status, link exists, target exists)")

    def check_directory_symlink_smb1_rmdir(self, fsctl, smb1share):
        result = self.smb1_delete_directory_symlink(
            fsctl, smb1share, rmdir=True)
        # Like RemoveDirectory on NTFS: the link goes, the
        # (non-empty) target stays
        self.assertEqual(
            result,
            (0, False, True),
            "(status, link exists, target exists)")

    def test_directory_symlink_smb1_unlink(self):
        """SMB1 unlink of a POSIX directory symlink fails"""
        self.check_directory_symlink_smb1_unlink(False, "nosymlinks")

    def test_directory_symlink_smb1_unlink_follow(self):
        """SMB1 unlink of a POSIX directory symlink fails, following"""
        self.check_directory_symlink_smb1_unlink(
            False, "nosymlinks_smb1allow")

    def test_directory_symlink_smb1_unlink_fsctl(self):
        """SMB1 unlink of a reparse point directory symlink fails"""
        self.check_directory_symlink_smb1_unlink(True, "nosymlinks")

    def test_directory_symlink_smb1_rmdir(self):
        """SMB1 rmdir removes a POSIX directory symlink"""
        self.check_directory_symlink_smb1_rmdir(False, "nosymlinks")

    def test_directory_symlink_smb1_rmdir_follow(self):
        """SMB1 rmdir removes a POSIX directory symlink, following"""
        self.check_directory_symlink_smb1_rmdir(
            False, "nosymlinks_smb1allow")

    def test_directory_symlink_smb1_rmdir_fsctl(self):
        """SMB1 rmdir removes a reparse point directory symlink"""
        self.check_directory_symlink_smb1_rmdir(True, "nosymlinks")

    def check_directory_symlink_invalid_disposition(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        # Directory opens don't allow these, a symlink is no exception
        for disposition in [libsmb.FILE_SUPERSEDE,
                            libsmb.FILE_OVERWRITE,
                            libsmb.FILE_OVERWRITE_IF]:
            with self.assertRaises(NTSTATUSError) as cm:
                smb2.create_ex(
                    symlink,
                    DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                    CreateDisposition=disposition,
                    CreateOptions=libsmb.FILE_DIRECTORY_FILE |
                    libsmb.FILE_OPEN_REPARSE_POINT)
            self.assertEqual(cm.exception.args[0],
                             ntstatus.NT_STATUS_INVALID_PARAMETER)

        # The link is still there
        (fd, _, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        smb2.close(fd)

    def test_directory_symlink_invalid_disposition(self):
        """Directory open of a POSIX directory symlink checks disposition"""
        self.check_directory_symlink_invalid_disposition(False)

    def test_directory_symlink_invalid_disposition_fsctl(self):
        """Directory open of a reparse point directory symlink checks
        disposition"""
        self.check_directory_symlink_invalid_disposition(True)

    def check_directory_symlink_nondir(self, fsctl):
        (smb2, symlink) = self.dir_symlink_setup(fsctl)

        # Like NTFS, a non-directory open of a link that is a
        # directory fails, only a directory open can remove it
        try:
            fd = smb2.create(symlink,
                             DesiredAccess=(sec.SEC_STD_DELETE |
                                            sec.SEC_FILE_READ_ATTRIBUTE),
                             CreateOptions=(libsmb.FILE_NON_DIRECTORY_FILE |
                                            libsmb.FILE_OPEN_REPARSE_POINT))
        except NTSTATUSError as e:
            self.assertEqual(e.args[0], ntstatus.NT_STATUS_FILE_IS_A_DIRECTORY)
        else:
            smb2.close(fd)
            self.fail("Non-directory open of a directory symlink succeeded")

        # The link and the target are still there
        self.verify_symlink(smb2, symlink, "tdir")
        fd = self.assertNoNTSTATUSError(smb2.create, "tdir\\f")
        smb2.close(fd)

    def test_directory_symlink_nondir(self):
        """Non-directory open of a POSIX directory symlink fails"""
        self.check_directory_symlink_nondir(False)

    def test_directory_symlink_nondir_fsctl(self):
        """Non-directory open of a reparse point directory symlink fails"""
        self.check_directory_symlink_nondir(True)

    def test_directory_symlink_nondir_posix(self):
        """A POSIX client opens a directory symlink as a non-directory

        For a POSIX client the link is a symlink, not a directory.
        """
        root = os.path.join(
            samba.tests.env_get_var_value("LOCAL_PATH"), "nosymlinks")
        tdir = "pdir"
        lnk = "plnk"

        os.mkdir(os.path.join(root, tdir))
        self.addCleanup(os.rmdir, os.path.join(root, tdir))
        os.symlink(tdir, os.path.join(root, lnk))
        self.addCleanup(self.remove_local, os.path.join(root, lnk))

        smb2 = libsmb.Conn(self.server_ip, "nosymlinks", self.lp,
                           self.creds, posix=True)
        self.assertTrue(smb2.have_posix())

        wire_mode = libsmb.unix_mode_to_wire(0o644)
        (fd, _, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            lnk,
            DesiredAccess=(sec.SEC_STD_DELETE |
                           sec.SEC_FILE_READ_ATTRIBUTE),
            CreateOptions=(libsmb.FILE_NON_DIRECTORY_FILE |
                           libsmb.FILE_OPEN_REPARSE_POINT),
            CreateContexts=[(libsmb.SMB2_CREATE_TAG_POSIX,
                             wire_mode.to_bytes(4, 'little'))])
        self.assertNoNTSTATUSError(smb2.delete_on_close, fd, 1)
        smb2.close(fd)

        # Just the link is gone
        self.assertFalse(os.path.lexists(os.path.join(root, lnk)))
        self.assertTrue(os.path.isdir(os.path.join(root, tdir)))

    def test_directory_symlink_retargeted_to_file(self):
        """A directory symlink stays a directory if its target becomes a file

        NTFS keeps FILE_ATTRIBUTE_DIRECTORY with the link, it is set
        when the link is created as a directory and does not depend on
        what the link points to. This documents that for Windows, set
        SYMLINK_VIA_FSCTL=1 and SMB2_SHARE. Samba stores the bit with
        a reparse point symlink as well, but a POSIX symlink has
        nowhere to keep it, there it is looked up in the target.
        """
        via_fsctl = samba.tests.env_get_var_value(
            "SYMLINK_VIA_FSCTL", allow_missing=True)
        if not via_fsctl:
            self.skipTest("Windows only, set SYMLINK_VIA_FSCTL=1")

        (smb2, symlink) = self.dir_symlink_setup(True)

        # Replace the target directory by a file of the same name
        self.clean_file(smb2, "tdir\\f")
        self.clean_file(smb2, "tdir")
        fd = smb2.create("tdir", CreateDisposition=libsmb.FILE_CREATE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, "tdir")

        # The link itself is unchanged
        self.verify_symlink(smb2, symlink, "tdir")

        (fd, cr, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
        self.addCleanup(smb2.close, fd)

        attrs = cr['file_attributes']
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                         libsmb.FILE_ATTRIBUTE_REPARSE_POINT)
        self.assertEqual(attrs & libsmb.FILE_ATTRIBUTE_DIRECTORY,
                         libsmb.FILE_ATTRIBUTE_DIRECTORY)

        # The client is told to follow the link, not asserted
        for name, opts in [
                ("follow link", 0),
                ("follow link as directory", libsmb.FILE_DIRECTORY_FILE)]:
            try:
                fd2 = smb2.create(
                    symlink,
                    DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                    CreateOptions=opts)
                smb2.close(fd2)
                print(f'{name}: opened')
            except NTSTATUSError as e:
                print(f'{name}: {e.args[1]}')

        # "del" on a directory symlink
        with self.assertRaises(NTSTATUSError) as cm:
            smb2.create(symlink,
                        DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                        CreateOptions=libsmb.FILE_NON_DIRECTORY_FILE |
                        libsmb.FILE_OPEN_REPARSE_POINT)
        self.assertEqual(cm.exception.args[0],
                         ntstatus.NT_STATUS_FILE_IS_A_DIRECTORY)

        # RemoveDirectory() removes just the link, the file stays
        (fd3, _, _) = self.assertNoNTSTATUSError(
            smb2.create_ex,
            symlink,
            DesiredAccess=sec.SEC_STD_DELETE |
            sec.SEC_FILE_READ_ATTRIBUTE,
            CreateOptions=libsmb.FILE_DIRECTORY_FILE |
            libsmb.FILE_OPEN_REPARSE_POINT)
        self.assertNoNTSTATUSError(smb2.delete_on_close, fd3, 1)
        smb2.close(fd3)

        fd4 = self.assertNoNTSTATUSError(smb2.create, "tdir")
        smb2.close(fd4)

    def test_query_directory_symlinks(self):
        """Query directory shows followed symlinks as their targets

        This is "follow symlinks = yes" behaviour, Samba specific.
        Windows lists symlinks as reparse points. Only POSIX
        symlinks are followed, reparse point symlinks created with
        FSCTL_SET_REPARSE_POINT are listed as reparse points.
        """
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        if share:
            self.skipTest("Following symlinks is Samba specific")
        share = "local_symlinks"
        smb2 = libsmb.Conn(self.server_ip, share, self.lp, self.creds)
        lnkconn = libsmb.Conn(
            self.server_ip, share, self.lp, self.creds, force_smb1=True)
        lnkconn.smb1_posix()

        fd = smb2.create("tfile",
                         DesiredAccess=sec.SEC_FILE_WRITE_DATA,
                         CreateDisposition=libsmb.FILE_CREATE)
        smb2.write(fd, b"0123456789", 0)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, "tfile")

        fd = smb2.create("tdir",
                         CreateDisposition=libsmb.FILE_CREATE,
                         CreateOptions=libsmb.FILE_DIRECTORY_FILE)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, "tdir")

        self.create_symlink(lnkconn, "tfile", "flnk")
        self.addCleanup(self.clean_file, lnkconn, "flnk")
        self.create_symlink(lnkconn, "tdir", "dlnk", directory=True)
        self.addCleanup(self.clean_file, lnkconn, "dlnk")
        self.create_symlink(lnkconn, "nonexistent", "dangling")
        self.addCleanup(self.clean_file, lnkconn, "dangling")

        entries = {f['name']: f for f in smb2.list("")}

        # A dangling symlink can't be followed and is hidden
        self.assertNotIn("dangling", entries)

        for name in ["tfile", "flnk", "tdir", "dlnk"]:
            self.assertIn(name, entries)
            self.assertEqual(
                entries[name]['attrib'] & libsmb.FILE_ATTRIBUTE_REPARSE_POINT,
                0, f'{name} is shown as a reparse point')
            self.assertEqual(entries[name]['reparse_tag'], 0)

        # Followed links look like their targets
        self.assertEqual(entries["flnk"]['size'], 10)
        self.assertEqual(
            entries["flnk"]['attrib'] & libsmb.FILE_ATTRIBUTE_DIRECTORY, 0)
        self.assertEqual(
            entries["dlnk"]['attrib'] & libsmb.FILE_ATTRIBUTE_DIRECTORY,
            libsmb.FILE_ATTRIBUTE_DIRECTORY)

    def check_symlink_to_fake_file(self, fsctl):
        share = samba.tests.env_get_var_value(
            "SMB2_SHARE", allow_missing=True)
        if share:
            self.skipTest("Fake files are Samba specific")
        smb2 = libsmb.Conn(
            self.server_ip, "nosymlinks", self.lp, self.creds)
        if fsctl:
            lnkconn = smb2
        else:
            lnkconn = self.symlink_conn("nosymlinks_smb1allow")
        symlink = "qlnk"

        # The name of the fake quota file. Resolving the target of the
        # symlink must not hand out the connection's cwd_fsp.
        target = "$Extend/$Quota:$Q:$INDEX_ALLOCATION"

        self.create_symlink(lnkconn, target, symlink)
        self.addCleanup(self.clean_file, lnkconn, symlink)

        for i in range(2):
            (fd, cr, _) = self.assertNoNTSTATUSError(
                smb2.create_ex,
                symlink,
                DesiredAccess=sec.SEC_FILE_READ_ATTRIBUTE,
                CreateOptions=libsmb.FILE_OPEN_REPARSE_POINT)
            smb2.close(fd)

        # A fake file is not a directory
        self.assertEqual(
            cr['file_attributes'] & libsmb.FILE_ATTRIBUTE_DIRECTORY, 0)

        # The share root must still be usable
        fd = smb2.create("tfile", CreateDisposition=libsmb.FILE_OVERWRITE_IF)
        smb2.close(fd)
        self.addCleanup(self.clean_file, smb2, "tfile")

    def test_symlink_to_fake_file(self):
        """A POSIX symlink to the fake quota file does not harm smbd"""
        self.check_symlink_to_fake_file(False)

    def test_symlink_to_fake_file_fsctl(self):
        """A reparse point symlink to the fake quota file"""
        self.check_symlink_to_fake_file(True)

if __name__ == '__main__':
    import unittest
    unittest.main()
