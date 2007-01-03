#!/usr/bin/env python

import tree, mapper

def search(node, found, level=0, prefix="$", register=False, debug=False):
  if node.type == "function":
    if register:
      name = node.get("name", False)
      if name != None and not name in found:
        # print "Name: %s" % funcName
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
          found.append(name)

  # e.g. var name1, name2 = "foo";
  elif register and node.type == "definition":
    name = node.get("identifier", False)

    if name != None:
      if not name in found:
        found.append(name)

  # Iterate over children
  if node.hasChildren():
    if node.type == "function":
      for child in node.children:
        search(child, found, level+1, prefix, register, debug)

    else:
      for child in node.children:
        search(child, found, level, prefix, register, debug)

  # Function closed
  if node.type == "function":

    # Debug
    if debug:
      for item in found:
        print "  %s<item>%s</item>" % (("  " * level), item)
      print "%s</scope>" % ("  " * level)

    # Iterate over content
    # Replace variables in current scope
    update(node, found, prefix, debug)
    del found[foundLen:]



def update(node, found, prefix="$", debug=False):
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

      if idenName != None and idenName in found:
        replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
        node.set("name", replName)

        if debug:
          print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Handle variable definition
  elif node.type == "definition":
    idenName = node.get("identifier", False)

    if idenName != None and idenName in found:
      replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
      node.set("identifier", replName)

      if debug:
        print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Handle function definition
  elif node.type == "function":
    idenName = node.get("name", False)

    if idenName != None and idenName in found:
      replName = "%s%s" % (prefix, mapper.convert(found.index(idenName)))
      node.set("name", replName)

      if debug:
        print "  - Replaced '%s' with '%s'" % (idenName, replName)

  # Iterate over children
  if node.hasChildren():
    for child in node.children:
      update(child, found, prefix, debug)
