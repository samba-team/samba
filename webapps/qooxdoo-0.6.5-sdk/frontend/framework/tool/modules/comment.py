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
#    * Fabian Jakobs (fjakobs)
#
################################################################################

import sys, string, re
import config, tree, textile



S_INLINE_COMMENT = "//.*"
R_INLINE_COMMENT = re.compile("^" + S_INLINE_COMMENT + "$")

R_INLINE_COMMENT_TIGHT = re.compile("^//\S+")
R_INLINE_COMMENT_PURE = re.compile("^//")



S_BLOCK_COMMENT = "/\*([^*]|[\n]|(\*+([^*/]|[\n])))*\*+/"
R_BLOCK_COMMENT = re.compile("^" + S_BLOCK_COMMENT + "$")

R_BLOCK_COMMENT_JAVADOC = re.compile("^/\*\*")
R_BLOCK_COMMENT_QTDOC = re.compile("^/\*!")
R_BLOCK_COMMENT_AREA = re.compile("^/\*\n\s*\*\*\*\*\*")
R_BLOCK_COMMENT_DIVIDER = re.compile("^/\*\n\s*----")
R_BLOCK_COMMENT_HEADER = re.compile("^/\* \*\*\*\*")

R_BLOCK_COMMENT_TIGHT_START = re.compile("^/\*\S+")
R_BLOCK_COMMENT_TIGHT_END = re.compile("\S+\*/$")
R_BLOCK_COMMENT_PURE_START = re.compile("^/\*")
R_BLOCK_COMMENT_PURE_END = re.compile("\*/$")

R_ATTRIBUTE = re.compile(r'[^{]@(\w+)\s*')
R_JAVADOC_STARS = re.compile(r'^\s*\*')



R_NAMED_TYPE = re.compile(r'^\s*([a-zA-Z0-9_\.#]+)\s*({([^}]+)})?')
R_SIMPLE_TYPE = re.compile(r'^\s*({([^}]+)})?')




VARPREFIXES = {
  "a" : "Array",
  "b" : "Boolean",
  "d" : "Date",
  "f" : "Function",
  "i" : "Integer",
  "h" : "Map",
  "m" : "Map",
  "n" : "Number",
  "o" : "Object",
  "r" : "RegExp",
  "s" : "String",
  "v" : "var",
  "w" : "Widget"
}

VARNAMES = {
  "a" : "Array",
  "arr" : "Array",

  "doc" : "Document",

  "e" : "Event",
  "ev" : "Event",
  "evt" : "Event",

  "el" : "Element",
  "elem" : "Element",
  "elm" : "Element",

  "ex" : "Exception",
  "exc" : "Exception",

  "flag" : "Boolean",
  "force" : "Boolean",

  "f" : "Function",
  "func" : "Function",

  "h" : "Map",
  "hash" : "Map",
  "map" : "Map",

  "node" : "Node",

  "n" : "Number",
  "num" : "Number",

  "o" : "Object",
  "obj" : "Object",

  "reg" : "RegExp",

  "s" : "String",
  "str" : "String",

  "win" : "Window"
}

VARDESC = {
  "propValue" : "Current value",
  "propOldValue" : "Previous value",
  "propData" : "Property configuration map"
}




def outdent(source, indent):
  return re.compile("\n\s{%s}" % indent).sub("\n", source)



def indent(source, indent):
  return re.compile("\n").sub("\n" + (" " * indent), source)



def correctInline(source):
  if R_INLINE_COMMENT_TIGHT.match(source):
    return R_INLINE_COMMENT_PURE.sub("// ", source)

  return source



def correctBlock(source):
  if not getFormat(source) in [ "javadoc", "qtdoc" ]:
    if R_BLOCK_COMMENT_TIGHT_START.search(source):
      source = R_BLOCK_COMMENT_PURE_START.sub("/* ", source)

    if R_BLOCK_COMMENT_TIGHT_END.search(source):
      source = R_BLOCK_COMMENT_PURE_END.sub(" */", source)

  return source



def correct(source):
  if source.startswith("//"):
    return correctInline(source)
  else:
    return correctBlock(source)



def isMultiLine(source):
  return source.find("\n") != -1



def getFormat(source):
  if R_BLOCK_COMMENT_JAVADOC.search(source):
    return "javadoc"
  elif R_BLOCK_COMMENT_QTDOC.search(source):
    return "qtdoc"
  elif R_BLOCK_COMMENT_AREA.search(source):
    return "area"
  elif R_BLOCK_COMMENT_DIVIDER.search(source):
    return "divider"
  elif R_BLOCK_COMMENT_HEADER.search(source):
    return "header"

  return "block"








def hasThrows(node):
  if node.type == "throw":
    return True

  if node.hasChildren():
    for child in node.children:
      if hasThrows(child):
        return True

  return False




def getReturns(node, found):
  if node.type == "function":
    pass

  elif node.type == "return":
    if node.getChildrenLength(True) > 0:
      val = "var"
    else:
      val = "void"

    if node.hasChild("expression"):
      expr = node.getChild("expression")
      if expr.hasChild("variable"):
        var = expr.getChild("variable")
        if var.getChildrenLength(True) == 1 and var.hasChild("identifier"):
          val = nameToType(var.getChild("identifier").get("name"))
        else:
          val = "var"

      elif expr.hasChild("constant"):
        val = expr.getChild("constant").get("constantType")

        if val == "number":
          val = expr.getChild("constant").get("detail")

      elif expr.hasChild("array"):
        val = "Array"

      elif expr.hasChild("map"):
        val = "Map"

      elif expr.hasChild("function"):
        val = "Function"

      elif expr.hasChild("call"):
        val = "call"

    if not val in found:
      found.append(val)

  elif node.hasChildren():
    for child in node.children:
      getReturns(child, found)

  return found



def nameToType(name):
  typ = "var"

  # Evaluate type from name
  if name in VARNAMES:
    typ = VARNAMES[name]

  elif len(name) > 1:
    if name[1].isupper():
      if name[0] in VARPREFIXES:
        typ = VARPREFIXES[name[0]]

  return typ



def nameToDescription(name):
  desc = "TODOC"

  if name in VARDESC:
    desc = VARDESC[name]

  return desc




def qt2javadoc(text):
  attribList = parseText(text, False)
  res = "/**"

  desc = getAttrib(attribList, "description")["text"]

  if "\n" in desc:
    res += "\n"

    for line in desc.split("\n"):
      res += " * %s\n" % line

    res += " "

  else:
    res += " %s " % desc

  res += "*/"

  return res


def parseNode(node):
  """Takes the last doc comment from the commentsBefore child, parses it and
  returns a Node representing the doc comment"""

  # Find the last doc comment
  commentsBefore = node.getChild("commentsBefore", False)
  if commentsBefore and commentsBefore.hasChildren():
    for child in commentsBefore.children:
      if child.type == "comment" and child.get("detail") in [ "javadoc", "qtdoc" ]:
        return parseText(child.get("text"))

  return []



def parseText(intext, format=True):
  # print "Parse: " + intext

  # Strip "/**", "/*!" and "*/"
  intext = intext[3:-2]

  # Strip leading stars in every line
  text = ""
  for line in intext.split("\n"):
    text += R_JAVADOC_STARS.sub("", line) + "\n"

  # Autodent
  text = autoOutdent(text)

  # Search for attributes
  desc = { "category" : "description", "text" : "" }
  attribs = [ desc ]
  pos = 0

  while True:
    mtch = R_ATTRIBUTE.search(text, pos)

    if mtch == None:
      prevText = text[pos:].rstrip()

      if len(attribs) == 0:
        desc["text"] = prevText
      else:
        attribs[-1]["text"] = prevText

      break

    prevText = text[pos:mtch.start(0)].rstrip()
    pos = mtch.end(0)

    if len(attribs) == 0:
      desc["text"] = prevText
    else:
      attribs[-1]["text"] = prevText

    attribs.append({ "category" : mtch.group(1), "text" : "" })

  # parse details
  for attrib in attribs:
    parseDetail(attrib, format)

  return attribs



def parseDetail(attrib, format=True):
  text = attrib["text"]

  if attrib["category"] in [ "param", "event", "see" ]:
    mtch = R_NAMED_TYPE.search(text)
  else:
    mtch = R_SIMPLE_TYPE.search(text)

  if mtch:
    text = text[mtch.end(0):]

    if attrib["category"] in [ "param", "event", "see" ]:
      attrib["name"] = mtch.group(1)
      # print ">>> NAME: %s" % mtch.group(1)
      remain = mtch.group(3)
    else:
      remain = mtch.group(2)

    if remain != None:
      defIndex = remain.rfind("?")
      if defIndex != -1:
        attrib["default"] = remain[defIndex+1:].strip()
        remain = remain[0:defIndex].strip()
        # print ">>> DEFAULT: %s" % attrib["default"]

      typValues = []
      for typ in remain.split("|"):
        typValue = typ.strip()
        arrayIndex = typValue.find("[")

        if arrayIndex != -1:
          arrayValue = (len(typValue) - arrayIndex) / 2
          typValue = typValue[0:arrayIndex]
        else:
          arrayValue = 0

        typValues.append({ "type" : typValue, "dimensions" : arrayValue })

      if len(typValues) > 0:
        attrib["type"] = typValues
        # print ">>> TYPE: %s" % attrib["type"]

  if format:
    attrib["text"] = formatText(text)
  else:
    attrib["text"] = cleanupText(text)

  if attrib["text"] == "":
    del attrib["text"]




def autoOutdent(text):
  lines = text.split("\n")

  if len(lines) <= 1:
    return text.strip()

  for line in lines:
    if len(line) > 0 and line[0] != " ":
      return text

  result = ""
  for line in lines:
    if len(line) >= 0:
      result += line[1:]

    result += "\n"

  return result



def cleanupText(text):
  #print "============= INTEXT ========================="
  #print text

  text = text.replace("<p>", "\n")
  text = text.replace("<br/>", "\n")
  text = text.replace("<br>", "\n")
  text = text.replace("</p>", " ")

  newline = False
  lines = text.split("\n")
  text = u""

  for line in lines:
    if line == "":
      if not newline:
        newline = True

    else:
      if text != "":
        text += "\n"

      if newline:
        text += "\n"
        newline = False

      text += line

  #print "============= OUTTEXT ========================="
  #print text

  return text



def formatText(text):
  text = cleanupText(text)

  #if "\n" in text:
  #  print
  #  print "------------- ORIGINAL ----------------"
  #  print text

  text = text.replace("<pre", "\n\n<pre").replace("</pre>", "</pre>\n\n")

  # encode to ascii leads into a translation of umlauts to their XML code.
  text = unicode(textile.textile(text.encode("utf-8"), output="ascii"))

  #if "\n" in text:
  #  print "------------- TEXTILED ----------------"
  #  print text

  return text








def getAttrib(attribList, category):
  for attrib in attribList:
    if attrib["category"] == category:
      return attrib



def getParam(attribList, name):
  for attrib in attribList:
    if attrib["category"] == "param":
      if attrib.has_key("name") and attrib["name"] == name:
        return attrib



def attribHas(attrib, key):
  if attrib != None and attrib.has_key(key) and not attrib[key] in [ "", None ]:
    return True

  return False



def splitText(orig, attrib=True):
  res = ""
  first = True

  for line in orig.split("\n"):
    if attrib:
      if first:
        res += " %s\n" % line
      else:
        res += " *   %s\n" % line

    else:
      res += " * %s\n" % line

    first = False

  if not res.endswith("\n"):
    res += "\n"

  return res



def parseType(vtype):
  typeText = ""

  firstType = True
  for entry in vtype:
    if not firstType:
      typeText += " | "

    typeText += entry["type"]

    if entry.has_key("dimensions") and entry["dimensions"] > 0:
      typeText += "[]" * entry["dimensions"]

    firstType = False

  return typeText




def fromNode(node, assignType, name, alternative, old=[]):
  #
  # description
  ##############################################################
  oldDesc = getAttrib(old, "description")

  if attribHas(oldDesc, "text"):
    newText = oldDesc["text"]
  else:
    newText = "{var} TODOC"

  if "\n" in newText:
    s = "/**\n%s\n-*/" % splitText(newText, False)
  else:
    s = "/** %s */" % newText


  #
  # other @attributes
  ##############################################################

  for attrib in old:
    cat = attrib["category"]

    if cat != "description":
      print " * Found unallowed attribute %s in comment for %s (node)" % (cat, name)

  return s




def fromFunction(func, assignType, name, alternative, old=[]):
  #
  # open comment
  ##############################################################
  s = "/**\n"


  #
  # description
  ##############################################################
  oldDesc = getAttrib(old, "description")

  if attribHas(oldDesc, "text"):
    newText = oldDesc["text"]
  else:
    newText = "TODOC"

  s += splitText(newText, False)
  s += " *\n"




  #
  # add @type
  ##############################################################
  if assignType != None:
    s += " * @type %s\n" % assignType
  else:
    s += " * @type unknown TODOC\n"




  #
  # add @name and @access
  ##############################################################
  if name != None and name != "construct":
    s += " * @name %s\n" % name

    if name.startswith("__"):
      s += " * @access private\n"
    elif name.startswith("_"):
      s += " * @access protected\n"
    else:
      s += " * @access public\n"



  #
  # add @alternative
  ##############################################################
  oldAlternative = getAttrib(old, "alternative")

  if alternative:
    if attribHas(oldAlternative, "text"):
      newText = oldDesc["text"]
    else:
      newText = "TODOC"

    s += " * @alternative%s" % splitText(newText)

    if not s.endswith("\n"):
      s += "\n"

  elif oldAlternative:
    print " * Removing old @alternative for %s" % name




  #
  # add @abstract
  ##############################################################
  oldAbstract = getAttrib(old, "abstract")

  first = func.getChild("body").getChild("block").getFirstChild(False, True)
  abstract = first and first.type == "throw"

  if abstract:
    if attribHas(oldAbstract, "text"):
      newText = oldDesc["text"]
    else:
      newText = ""

    s += " * @abstract%s" % splitText(newText)

    if not s.endswith("\n"):
      s += "\n"

  elif oldAbstract:
    print " * Removing old @abstract for %s" % name






  #
  # add @param
  ##############################################################
  params = func.getChild("params")
  if params.hasChildren():
    for child in params.children:
      if child.type == "variable":
        newName = child.getChild("identifier").get("name")
        newType = newTypeText = nameToType(newName)
        newDefault = ""
        newText = nameToDescription(newName)

        oldParam = getParam(old, newName)

        # Get type and text from old content
        if oldParam:
          if attribHas(oldParam, "type"):
            newTypeText = parseType(oldParam["type"])

          if attribHas(oldParam, "defaultValue"):
            newDefault = oldParam["defaultValue"]

          if attribHas(oldParam, "text"):
            newText = oldParam["text"].strip()

        s += " * @param %s {%s%s}%s" % (newName, newTypeText, newDefault, splitText(newText))

        if not s.endswith("\n"):
          s += "\n"





  #
  # add @return
  ##############################################################
  if name != "construct":
    oldReturn = getAttrib(old, "return")

    newType = "void"
    newText = ""

    # Get type and text from old content
    if oldReturn:
      if attribHas(oldReturn, "type"):
        newType = parseType(oldReturn["type"])

      if attribHas(oldReturn, "text"):
        newText = oldReturn["text"].strip()

    # Try to autodetect the type
    if newType == "void":
      returns = getReturns(func.getChild("body"), [])

      if len(returns) > 0:
        newType = " | ".join(returns)
      elif name != None and name.startswith("is") and name[3].isupper():
        newType = "boolean"

    # Add documentation hint in non void cases
    if newType != "void" and newText == "":
      newText = "TODOC"

    s += " * @return {%s}%s" % (newType, splitText(newText))

    if not s.endswith("\n"):
      s += "\n"






  #
  # add @throws
  ##############################################################
  oldThrows = getAttrib(old, "throws")

  if hasThrows(func):
    if oldThrows and attribHas(oldThrows, "text"):
      newText = oldThrows["text"]
    elif abstract:
      newText = "the abstract function warning."
    else:
      newText = "TODOC"

    s += " * @throws%s" % splitText(newText)

    if not s.endswith("\n"):
      s += "\n"

  elif oldThrows:
    print " * Removing old @throw attribute in comment for %s" % name




  #
  # other @attributes
  ##############################################################

  for attrib in old:
    cat = attrib["category"]

    if cat in [ "see", "author", "deprecated", "exception", "since", "version", "abstract", "overridden" ]:
      s += " * @%s" % cat

      if attribHas(attrib, "text"):
        s += splitText(attrib["text"])

      if not s.endswith("\n"):
        s += "\n"

    elif not cat in [ "description", "type", "name", "access", "alternative", "abstract", "param", "return", "throws" ]:
      print " * Found unallowed attribute %s in comment for %s (function)" % (cat, name)





  #
  # close comment
  ##############################################################
  s += " */"

  return s



def fill(node):
  if node.type in [ "comment", "commentsBefore", "commentsAfter" ]:
    return

  if node.hasParent():
    target = node

    if node.type == "function":
      name = node.get("name", False)
    else:
      name = ""

    alternative = False
    assignType = None

    if name != None:
      assignType = "function"

    # move to hook operation
    while target.parent.type in [ "first", "second", "third" ] and target.parent.parent.type == "operation" and target.parent.parent.get("operator") == "HOOK":
      alternative = True
      target = target.parent.parent

    # move comment to assignment
    while target.parent.type == "right" and target.parent.parent.type == "assignment":
      target = target.parent.parent
      if target.hasChild("left"):
        left = target.getChild("left")
        if left and left.hasChild("variable"):
          var = left.getChild("variable")
          last = var.getLastChild(False, True)
          if last and last.type == "identifier":
            name = last.get("name")
            assignType = "object"

          for child in var.children:
            if child.type == "identifier":
              if child.get("name") in [ "prototype", "Proto" ]:
                assignType = "member"
              elif child.get("name") in [ "class", "base", "Class" ]:
                assignType = "static"

      elif target.parent.type == "definition":
        name = target.parent.get("identifier")
        assignType = "definition"

    # move to definition
    if target.parent.type == "assignment" and target.parent.parent.type == "definition" and target.parent.parent.parent.getChildrenLength(True) == 1:
      target = target.parent.parent.parent
      assignType = "function"


    # move comment to keyvalue
    if target.parent.type == "value" and target.parent.parent.type == "keyvalue":
      target = target.parent.parent
      name = target.get("key")
      assignType = "map"

      if name == "construct":
        assignType = "constructor"

      if target.parent.type == "map" and target.parent.parent.type == "value" and target.parent.parent.parent.type == "keyvalue":
        paname = target.parent.parent.parent.get("key")

        if paname == "members":
          assignType = "member"

        elif paname == "statics":
          assignType = "static"

    # filter stuff, only add comments to member and static values and to all functions
    if assignType in [ "member", "static" ] or node.type == "function":

      if not hasattr(target, "documentationAdded") and target.parent.type != "params":
        old = []

        # create commentsBefore
        if target.hasChild("commentsBefore"):
          commentsBefore = target.getChild("commentsBefore")

          if commentsBefore.hasChild("comment"):
            for child in commentsBefore.children:
              if child.get("detail") in [ "javadoc", "qtdoc" ]:
                old = parseText(child.get("text"), False)
                commentsBefore.removeChild(child)
                break

        else:
          commentsBefore = tree.Node("commentsBefore")
          target.addChild(commentsBefore)

        # create comment node
        commentNode = tree.Node("comment")

        if node.type == "function":
          commentNode.set("text", fromFunction(node, assignType, name, alternative, old))
        else:
          commentNode.set("text", fromNode(node, assignType, name, alternative, old))

        commentNode.set("detail", "javadoc")
        commentNode.set("multiline", True)

        commentsBefore.addChild(commentNode)

        # in case of alternative methods, use the first one, ignore the others
        target.documentationAdded = True





  if node.hasChildren():
    for child in node.children:
      fill(child)
