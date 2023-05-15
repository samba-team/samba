# Unix SMB/CIFS implementation.
#
# validators
#
# Copyright (C) Catalyst.Net Ltd. 2023
#
# Written by Rob van der Linde <rob@catalyst.net.nz>
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

from abc import ABCMeta, abstractmethod


class ValidationError(Exception):
    pass


class Validator(metaclass=ABCMeta):

    @abstractmethod
    def __call__(self, field, value):
        pass


class Range(Validator):
    """Checks if the value is within range min ... max."""

    def __init__(self, min=None, max=None):
        if min is None and max is None:
            raise ValueError("Range without a min and max doesn't make sense.")

        self.min = min
        self.max = max

    def __call__(self, field, value):
        """Check if value is within the range min ... max.

        It is possible to omit min, or omit max, in which case a more
        tailored error message is returned.
        """
        if self.min is not None and self.max is None:
            if value < self.min:
                raise ValidationError(f"{field} must be at least {self.min}")

        elif self.min is None and self.max is not None:
            if value > self.max:
                raise ValidationError(
                    f"{field} cannot be greater than {self.max}")

        elif self.min is not None and self.max is not None:
            if value < self.min or value > self.max:
                raise ValidationError(
                    f"{field} must be between {self.min} and {self.max}")


class OneOf(Validator):
    """Checks if the value is in a list of possible choices."""

    def __init__(self, choices):
        self.choices = sorted(choices)

    def __call__(self, field, value):
        if value not in self.choices:
            allowed_choices = ", ".join(self.choices)
            raise ValidationError(f"{field} must be one of: {allowed_choices}")
