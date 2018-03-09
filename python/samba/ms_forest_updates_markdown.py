# Create forest updates ldif from Github markdown
#
# Each update is converted to an ldif then gets written to a corresponding
# .LDF output file or stored in a dictionary.
#
# Only add updates can generally be applied.
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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

from __future__ import print_function
"""Generate LDIF from Github documentation."""

import re
import os
import markdown
import xml.etree.ElementTree as ET


# Display specifier updates or otherwise (ignored in forest_update.py)
def noop(description, attributes, sd):
    return (None, None, [], None)


# ACE addition updates (ignored in forest_update.py)
def parse_grant(description, attributes, sd):
    return ('modify', None, [], sd if sd.lower() != 'n/a' else None)


# Addition of new objects to the directory (most are applied in forest_update.py)
def parse_add(description, attributes, sd):
    dn = extract_dn(description)
    return ('add', dn, extract_attrib(dn, attributes), sd if sd.lower() != 'n/a' else None)


# Set of a particular attribute (ignored in forest_update.py)
def parse_set(description, attributes, sd):
    return ('modify', extract_dn_or_none(description),
            extract_replace_attrib(attributes),
            sd if sd.lower() != 'n/a' else None)


# Set of a particular ACE (ignored in forest_update.py)
# The general issue is that the list of DNs must be generated dynamically
def parse_ace(description, attributes, sd):

    def extract_dn_ace(text):
        if 'Sam-Domain' in text:
            return ('${DOMAIN_DN}', 'CN=Sam-Domain,${SCHEMA_DN}')
        elif 'Domain-DNS' in text:
            return ('${...}', 'CN=Domain-DNS,${SCHEMA_DN}')

        return None

    return [('modify', extract_dn_ace(description)[0],
             ['replace: nTSecurityDescriptor',
              'nTSecurityDescriptor: ${DOMAIN_SCHEMA_SD}%s' % sd], None),
            ('modify', extract_dn_ace(description)[1],
             ['replace: defaultSecurityDescriptor',
              'defaultSecurityDescriptor: ${OLD_SAMBA_SD}%s' % sd], None)]


# We are really only interested in 'Created' items
operation_map = {
    # modify
    'Granting': parse_grant,
    # add
    'Created': parse_add,
    # modify
    'Set': parse_set,
    # modify
    'Added ACE': parse_ace,
    # modify
    'Updated': parse_set,
    # unknown
    'Call': noop
}


def extract_dn(text):
    """
    Extract a DN from the textual description
    :param text:
    :return: DN in string form
    """
    text = text.replace(' in the Schema partition.', ',${SCHEMA_DN}')
    text = text.replace(' in the Configuration partition.', ',${CONFIG_DN}')
    dn = re.search('([CDO][NCU]=.*?,)*([CDO][NCU]=.*)', text).group(0)

    # This should probably be also fixed upstream
    if dn == 'CN=ad://ext/AuthenticationSilo,CN=Claim Types,CN=Claims Configuration,CN=Services':
        return 'CN=ad://ext/AuthenticationSilo,CN=Claim Types,CN=Claims Configuration,CN=Services,${CONFIG_DN}'

    return dn


def extract_dn_or_none(text):
    """
    Same as above, but returns None if it doesn't work
    :param text:
    :return: DN or None
    """
    try:
        return extract_dn(text)
    except:
        return None


def save_ldif(filename, answers, out_folder):
    """
    Save ldif to disk for each updates
    :param filename: filename use ([OPERATION NUM]-{GUID}.ldif)
    :param answers: array of tuples generated with earlier functions
    :param out_folder: folder to prepend
    """
    path = os.path.join(out_folder, filename)
    with open(path, 'w') as ldif:
        for answer in answers:
            change, dn, attrib, sd = answer
            ldif.write('dn: %s\n' % dn)
            ldif.write('changetype: %s\n' % change)
            if len(attrib) > 0:
                ldif.write('\n'.join(attrib) + '\n')
            if sd is not None:
                ldif.write('nTSecurityDescriptor: D:%s\n' % sd)
            ldif.write('-\n\n')


def save_array(guid, answers, out_dict):
    """
    Save ldif to an output dictionary
    :param guid: GUID to store
    :param answers: array of tuples generated with earlier functions
    :param out_dict: output dictionary
    """
    ldif = ''
    for answer in answers:
        change, dn, attrib, sd = answer
        ldif += 'dn: %s\n' % dn
        ldif += 'changetype: %s\n' % change
        if len(attrib) > 0:
            ldif += '\n'.join(attrib) + '\n'
        if sd is not None:
            ldif += 'nTSecurityDescriptor: D:%s\n' % sd
        ldif += '-\n\n'

    out_dict[guid] = ldif


def extract_attrib(dn, attributes):
    """
    Extract the attributes as an array from the attributes column
    :param dn: parsed from markdown
    :param attributes: from markdown
    :return: attribute array (ldif-type format)
    """
    attrib = [x.lstrip('- ') for x in attributes.split('-   ') if x.lower() != 'n/a' and x != '']
    attrib = [x.replace(': True', ': TRUE') if x.endswith(': True') else x for x in attrib]
    attrib = [x.replace(': False', ': FALSE') if x.endswith(': False') else x for x in attrib]
    # We only have one such value, we may as well skip them all consistently
    attrib = [x for x in attrib if not x.lower().startswith('msds-claimpossiblevalues')]

    return attrib


def extract_replace_attrib(attributes):
    """
    Extract the attributes as an array from the attributes column
    (for replace)
    :param attributes: from markdown
    :return: attribute array (ldif-type format)
    """
    lines = [x.lstrip('- ') for x in attributes.split('-   ') if x.lower() != 'n/a' and x != '']
    lines = [('replace: %s' % line.split(':')[0], line) for line in lines]
    lines = [line for pair in lines for line in pair]
    return lines


def innertext(tag):
    return (tag.text or '') + \
        ''.join(innertext(e) for e in tag) + \
        (tag.tail or '')


def read_ms_markdown(in_file, out_folder=None, out_dict={}):
    """
    Read Github documentation to produce forest wide udpates
    :param in_file: Forest-Wide-Updates.md
    :param out_folder: output folder
    :param out_dict: output dictionary
    """

    with open(in_file) as update_file:
        # There is a hidden ClaimPossibleValues in this md file
        html = markdown.markdown(re.sub(r'CN=<forest root domain.*?>',
                                        '${FOREST_ROOT_DOMAIN}',
                                        update_file.read()),
                                 output_format='xhtml')

    html = html.replace('CN=Schema,%ws', '${SCHEMA_DN}')

    tree = ET.fromstring('<root>' + html + '</root>')

    for node in tree:
        if node.text and node.text.startswith('|Operation'):
            # Strip first and last |
            updates = [x[1:len(x)-1].split('|') for x in
                       ET.tostring(node,method='text').splitlines()]
            for update in updates[2:]:
                output = re.match('Operation (\d+): {(.*)}', update[0])
                if output:
                    # print output.group(1), output.group(2)
                    guid = output.group(2)
                    filename = "%s-{%s}.ldif" % (output.group(1).zfill(4), guid)

                found = False

                if update[3].startswith('Created') or update[1].startswith('Added ACE'):
                    # Trigger the security descriptor code
                    # Reduce info to just the security descriptor
                    update[3] = update[3].split(':')[-1]

                    result = parse_ace(update[1], update[2], update[3])

                    if filename and out_folder is not None:
                        save_ldif(filename, result, out_folder)
                    else:
                        save_array(guid, result, out_dict)

                    continue

                for operation in operation_map:
                    if update[1].startswith(operation):
                        found = True

                        result = operation_map[operation](update[1], update[2], update[3])

                        if filename and out_folder is not None:
                            save_ldif(filename, [result], out_folder)
                        else:
                            save_array(guid, [result], out_dict)

                        break

                if not found:
                    raise Exception(update)

            # print ET.tostring(node, method='text')

if __name__ == '__main__':
    import sys

    out_folder = ''

    if len(sys.argv) == 0:
        print("Usage: %s <Forest-Wide-Updates.md> [<output folder>]" % (sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    in_file = sys.argv[1]
    if len(sys.argv) > 2:
        out_folder = sys.argv[2]

    read_ms_markdown(in_file, out_folder)
