#!/usr/bin/env python
################################################################################
#
#  qooxdoo - the new era of web development
#
#  http://qooxdoo.org
#
#  Copyright:
#    2006-2007 1&1 Internet AG, Germany, http://www.1and1.org
#
#  License:
#    LGPL: http://www.gnu.org/licenses/lgpl.html
#    EPL: http://www.eclipse.org/org/documents/epl-v10.php
#    See the LICENSE file in the project's top-level directory for details.
#
#  Authors:
#    * Sebastian Werner (wpbasti)
#    * Alessandro Sala (asala)
#
################################################################################

import tree, mapper

def skip(name, prefix):
	return len(prefix) > 0 and name[:len(prefix)] == prefix

def search(node, found, level=0, prefix="$", skipPrefix="", register=False, debug=False):
  if node.type == "function":
    if register:
      name = node.get("name", False)
      if name != None and not name in found:
        # print "Name: %s" % name
        found.append(name)

    foundLen = len(found)
    register = True

    if debug:
      print "\n%s<scope line='%s'>" % (("  " * level), node.get("line"))

  # e.g. func(name1, name2);
  elif register and node.type == "variable" and node.hasChildren() and len(node.children) == 1:
    if node.parent.type == "params" and node.parent.parent.type != "call":
      first = node.getFirstChild()

      if first.type == "identifier":
        name = first.get("name")

        if not name in found:
          # print "Name: %s" % name
          found.append(name)

  # e.g. var name1, name2 = "foo";
  elif register and node.type == "definition":
    name = node.get("identifier", False)

    if name != None:
      if not name in found:
        # print "Name: %s" % name
        found.append(name)

  # Iterate over children
  if node.hasChildren():
    if node.type == "function":
      for child in node.children:
        search(child, found, level+1, prefix, skipPrefix, register, debug)

    else:
      for child in node.children:
        search(child, found, level, prefix, skipPrefix, register, debug)

  # Function closed
  if node.type == "function":

    # Debug
    if debug:
      for item in found:
        print "  %s<item>%s</item>" % (("  " * level), item)
      print "%s</scope>" % ("  " * level)

    # Iterate over content
    # Replace variables in current scope
    update(node, found, prefix, skipPrefix, debug)
    del found[foundLen:]



def update(node, found, prefix="$", skipPrefix="", debug=False):

  # Handle all identifiers
  if node.type == "identifier":

    isFirstChild = False
    isVariableMember = False

    if node.parent.type == "variable":
      isVariableMember = True
      varParent = node.parent.parent

      if not (varParent.type == "right" and varParent.parent.type == "accessor"):
        isFirstChild = node.parent.getFirstChild(True, True) == node

    elif node.parent.type == "identifier" and node.parent.parent.type == "accessor":
      isVariableMember = True
      accessor = node.parent.parent
      isFirstChild = accessor.parent.getFirstChild(True, True) == accessor

    # inside a variable parent only respect the first member
    if not isVariableMember or isFirstChild:
      idenName = node.get("name", False)

      if idenName != None and idenName in found and not skip(idenName, skipPrefix):
        replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
        node.set("name", replName)

        if debug:
          print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Handle variable definition
  elif node.type == "definition":
    idenName = node.get("identifier", False)

    if idenName != None and idenName in found and not skip(idenName, skipPrefix):
      replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
      node.set("identifier", replName)

      if debug:
        print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Handle function definition
  elif node.type == "function":
    idenName = node.get("name", False)

    if idenName != None and idenName in found and not skip(idenName, skipPrefix):
      replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
      node.set("name", replName)

      if debug:
        print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Iterate over children
  if node.hasChildren():
    for child in node.children:
      update(child, found, prefix, skipPrefix, debug)
