# samba-tool commands to generate a Certificate Signing Request for a computer’s
# certificate
#
# Copyright (C) Catalyst.Net Ltd 2025
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from typing import Optional

from cryptography.hazmat.primitives import serialization
import samba.getopt as options
from samba.netcmd import Command, Option
from samba.netcmd import exception_to_command_error

from samba.domain.models import Computer
from samba.domain.models.exceptions import ModelError
from samba.generate_csr import generate_csr


class cmd_computer_generate_csr(Command):
    """Generate a PEM‐encoded Certificate Signing Request for a computer."""

    synopsis = "%prog <computername> <subject_name> <private_key_filename> <output_filename> [options]"

    takes_args = [
        "computername",
        "subject_name",
        "private_key_filename",
        "output_filename",
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option(
            "--private-key-encoding",
            default="auto",
            choices=("pem", "der", "auto"),
            help="Private key encoding (optional)",
        ),
        Option(
            "--private-key-pass",
            help="Password to decrypt private key (optional)",
        ),
    ]

    @exception_to_command_error(ValueError, ModelError, FileNotFoundError)
    def run(
        self,
        computername: str,
        subject_name: str,
        private_key_filename: str,
        output_filename: str,
        *,
        hostopts: Optional[options.HostOptions] = None,
        sambaopts: Optional[options.SambaOptions] = None,
        credopts: Optional[options.CredentialsOptions] = None,
        private_key_encoding: Optional[str] = "auto",
        private_key_pass: Optional[str] = None,
    ):
        if private_key_encoding == "auto":
            private_key_encoding = None

        samdb = self.ldb_connect(hostopts, sambaopts, credopts)
        computer: Computer = Computer.find(samdb, computername)

        csr = generate_csr(
            samdb,
            computer,
            subject_name,
            private_key_filename,
            private_key_encoding=private_key_encoding,
            private_key_pass=private_key_pass,
        )

        serialized = csr.public_bytes(serialization.Encoding.PEM)
        with open(output_filename, "wb") as output_file:
            _ = output_file.write(serialized)
