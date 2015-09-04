pyiso8601: ISO 8601 Parsing for Python
======================================

.. image:: https://pypip.in/d/iso8601/badge.png

This module parses the most common forms of ISO 8601 date strings (e.g. 2007-01-14T20:34:22+00:00) into datetime objects.

>>> import iso8601
>>> iso8601.parse_date("2007-01-25T12:00:00Z")
datetime.datetime(2007, 1, 25, 12, 0, tzinfo=<iso8601.Utc>)
>>>

This module is released under a MIT license.

If you want more full featured parsing look at:

- http://labix.org/python-dateutil - python-dateutil

Parsed Formats
==============

You can parse full date + times, or just the date. In both cases a datetime instance is returned but with missing times defaulting to 0, and missing days / months defaulting to 1.

Dates
-----

- YYYY-MM-DD
- YYYYMMDD
- YYYY-MM (defaults to 1 for the day)
- YYYY (defaults to 1 for month and day)

Times
-----

- hh:mm:ss.nn
- hhmmss.nn
- hh:mm (defaults to 0 for seconds)
- hhmm (defaults to 0 for seconds)
- hh (defaults to 0 for minutes and seconds)

Time Zones
----------

- Nothing uses the default timezone given (UTC).
- Z (UTC)
- +/-hh:mm
- +/-hhmm
- +/-hh

Where it Differs From ISO 8601
==============================

Known differences from the ISO 8601 spec:

- You can use a " " (space) instead of T for separating date from time.
- Days and months without a leading 0 (2 vs 02) will be parsed.
- If time zone information is omitted the default time zone given is used (which in turn defaults to UTC). Use a default of None to yield naive datetime instances.

Installation
============

To install simply use pip::

    pip install iso8601


API
===

.. autofunction:: iso8601.parse_date

.. autoexception:: iso8601.ParseError

Authors
=======

Currently active committers:

- Michael Twomey
- Julien Danjou
