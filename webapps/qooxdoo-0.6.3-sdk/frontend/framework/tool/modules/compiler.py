#!/usr/bin/env python

import sys, string, re, optparse
import config, tokenizer, filetool, treegenerator, variableoptimizer, comment, tree

KEY = re.compile("^[A-Za-z0-9_]+$")
INDENTSPACES = 2



def compileToken(name, compact=False):
  global pretty


  if name in [ "INC", "DEC", "TYPEOF" ]:
    pass

  elif name in [ "INSTANCEOF", "IN" ]:
    space()

  elif not compact and pretty:
    space()



  if name == None:
    write("=")

  elif name in [ "TYPEOF", "INSTANCEOF", "IN" ]:
    write(name.lower())

  else:
    for key in config.JSTOKENS:
      if config.JSTOKENS[key] == name:
        write(key)



  if name in [ "INC", "DEC" ]:
    pass

  elif name in [ "TYPEOF", "INSTANCEOF", "IN" ]:
    space()

  elif not compact and pretty:
    space()


def space(force=True):
  global indent
  global result
  global pretty
  global afterLine
  global afterBreak

  if not force and not pretty:
    return

  if afterBreak or afterLine or result.endswith(" ") or result.endswith("\n"):
    return

  result += " "


def write(txt=""):
  global indent
  global result
  global pretty
  global breaks
  global afterLine
  global afterBreak
  global afterDivider
  global afterArea

  # strip remaining whitespaces
  if (afterLine or afterBreak or afterDivider or afterArea) and result.endswith(" "):
    result = result.rstrip()

  if pretty:
    # handle new line wishes
    if afterArea:
      nr = 9
    elif afterDivider:
      nr = 5
    elif afterBreak:
      nr = 2
    elif afterLine:
      nr = 1
    else:
      nr = 0

    while not result.endswith("\n" * nr):
      result += "\n"

  elif breaks and not result.endswith("\n"):
    if afterArea or afterDivider or afterBreak or afterLine:
      result += "\n"

  # reset
  afterLine = False
  afterBreak = False
  afterDivider = False
  afterArea = False

  # add indent (if needed)
  if pretty and result.endswith("\n"):
    result += (" " * (INDENTSPACES * indent))

  # append given text
  result += txt


def area():
  global afterArea
  afterArea = True


def divide():
  global afterDivider
  afterDivider = True


def sep():
  global afterBreak
  afterBreak = True


def nosep():
  global afterBreak
  afterBreak = False


def line():
  global afterLine
  afterLine = True


def noline():
  global afterLine
  global afterBreak
  global afterDivider
  global afterArea

  afterLine = False
  afterBreak = False
  afterDivider = False
  afterArea = False


def plus():
  global indent
  indent += 1


def minus():
  global indent
  indent -= 1


def semicolon():
  global result
  global breaks

  noline()

  if not (result.endswith("\n") or result.endswith(";")):
    write(";")

    if breaks:
      result += "\n"


def commentNode(node):
  global pretty

  if not pretty:
    return

  commentText = ""
  commentIsInline = False

  comment = node.getChild("commentsAfter", False)

  if comment and not comment.get("inserted", False):
    for child in comment.children:
      if not child.isFirstChild():
        commentText += " "

      commentText += child.get("text")

      if child.get("detail") == "inline":
        commentIsInline = True

    if commentText != "":
      space()
      write(commentText)

      if commentIsInline:
        line()
      else:
        space()

      comment.set("inserted", True)



def postProcessMap(m):
  if m.get("maxKeyLength", False) != None:
    return

  maxKeyLength = 0
  alignValues = True

  if m.hasChildren():
    for keyvalue in m.children:
      if keyvalue.type != "keyvalue":
        continue

      currKeyLength = len(keyvalue.get("key"))

      if keyvalue.get("quote", False) != None:
        currKeyLength += 2

      if currKeyLength > maxKeyLength:
        maxKeyLength = currKeyLength

      if alignValues and keyvalue.getChild("value").isComplex():
        alignValues = False

  m.set("maxKeyLength", maxKeyLength)
  m.set("alignValues", alignValues)





def compile(node, enablePretty=True, enableBreaks=False, enableDebug=False):
  global indent
  global result
  global pretty
  global debug
  global breaks
  global afterLine
  global afterBreak
  global afterDivider
  global afterArea

  indent = 0
  result = u""
  pretty = enablePretty
  debug = enableDebug
  breaks = enableBreaks
  afterLine = False
  afterBreak = False
  afterDivider = False
  afterArea = False

  if enablePretty:
    comment.fill(node)

  compileNode(node)

  return result










def compileNode(node):

  global pretty
  global indent




  #####################################################################################################################
  # Recover styling
  #####################################################################################################################

  if pretty:
    # Recover exclicit breaks
    if node.get("breakBefore", False) and not node.isFirstChild(True):
      sep()

    # Additional explicit break before complex blocks
    if node.hasParent() and not node.isFirstChild(True) and node.parent.type in [ "block", "file"] and node.isComplex():
      sep()



  #####################################################################################################################
  # Insert comments before
  #####################################################################################################################

  if pretty:
    if node.getChild("commentsBefore", False) != None:
      commentCounter = 0
      commentsBefore = node.getChild("commentsBefore")
      isFirst = node.isFirstChild()
      previous = node.getPreviousSibling(False, True)

      if previous and previous.type in [ "case", "default" ]:
        inCase = True
      else:
        inCase = False

      inOperation = node.parent.type in [ "first", "second", "third" ] and node.parent.parent.type == "operation"

      for child in commentsBefore.children:
        docComment = child.get("detail") in [ "javadoc", "qtdoc" ]
        headComment = child.get("detail") == "header"
        areaComment = child.get("detail") == "area"
        divComment = child.get("detail") == "divider"
        blockComment = child.get("detail") ==  "block"
        singleLineBlock = child.get("detail") != "inline" and child.get("multiline") == False

        if not child.isFirstChild():
          pass

        elif inCase:
          pass

        elif singleLineBlock:
          if child.get("begin"):
            sep()
          else:
            space()

        elif areaComment and not isFirst:
          area()

        elif divComment and not isFirst:
          divide()

        elif not isFirst:
          sep()

        elif inOperation:
          sep()

        elif not headComment:
          line()

        # reindenting first
        text = child.get("text")

        if child.get("detail") == "qtdoc":
          text = comment.qt2javadoc(text)

        write(comment.indent(text, INDENTSPACES * indent))

        if singleLineBlock:
          if child.get("detail") in [ "javadoc", "qtdoc" ]:
            line()
          elif child.get("end"):
            sep()
          else:
            space()

        # separator after divider/head comments and after block comments which are not for documentation
        elif headComment or areaComment or divComment or blockComment:
          sep()

        else:
          line()






  #####################################################################################################################
  # Opening...
  #####################################################################################################################

  #
  # OPEN: FINALLY
  ##################################

  if node.type == "finally":
    write("finally")


  #
  # OPEN: DELETE
  ##################################

  elif node.type == "delete":
    write("delete")
    space()


  #
  # OPEN: THROW
  ##################################

  elif node.type == "throw":
    write("throw")
    space()


  #
  # OPEN: NEW
  ##################################

  elif node.type == "instantiation":
    write("new")
    space()


  #
  # OPEN: RETURN
  ##################################

  elif node.type == "return":
    write("return")

    if node.hasChildren():
      space()


  #
  # OPEN: DEFINITION LIST
  ##################################

  elif node.type == "definitionList":
    write("var")
    space()


  #
  # OPEN: BREAK
  ##################################

  elif node.type == "break":
    write("break")

    if node.get("label", False):
      space()
      write(node.get("label", False))


  #
  # OPEN: CONTINUE
  ##################################

  elif node.type == "continue":
    write("continue")

    if node.get("label", False):
      space()
      write(node.get("label", False))


  #
  # OPEN: FUNCTION
  ##################################

  elif node.type == "function":
    write("function")

    functionName = node.get("name", False)
    if functionName != None:
      space()
      write(functionName)


  #
  # OPEN: IDENTIFIER
  ##################################

  elif node.type == "identifier":
    name = node.get("name", False)
    if name != None:
      write(name)


  #
  # OPEN: DEFINITION
  ##################################

  elif node.type == "definition":
    if node.parent.type != "definitionList":
      write("var")
      space()

    write(node.get("identifier"))


  #
  # OPEN: CONSTANT
  ##################################

  elif node.type == "constant":
    if node.get("constantType") == "string":
      if node.get("detail") == "singlequotes":
        write("'")
      else:
        write('"')

      write(node.get("value"))

      if node.get("detail") == "singlequotes":
        write("'")
      else:
        write('"')

    else:
      write(node.get("value"))


  #
  # OPEN: COMMENT
  ##################################

  elif node.type == "comment":
    if pretty:
      # insert a space before and no newline in the case of after comments
      if node.get("connection") == "after":
        noline()
        space()

      write(node.get("text"))

      # new line after inline comment (for example for syntactical reasons)
      if node.get("detail") == "inline":
        line()

      else:
        space()


  #
  # OPEN: RIGHT
  ##################################

  elif node.type == "right":
    if node.parent.type == "accessor":
      write(".")






  #
  # OPEN: ASSIGNMENT
  ##################################

  elif node.type == "assignment":
    if node.parent.type == "definition":
      oper = node.get("operator", False)

      realNode = node.parent.parent

      # be compact in for-loops
      compact = realNode.hasParent() and realNode.parent.type in [ "first", "second", "third" ] and realNode.parent.parent.type == "loop" and realNode.parent.parent.get("loopType") == "FOR"
      compileToken(oper, compact)





  #
  # OPEN: KEY
  ##################################

  elif node.type == "key":
    if node.parent.type == "accessor":
      write("[")


  #
  # OPEN: GROUP
  ##################################

  elif node.type == "group":
    write("(")


  #
  # OPEN: VOID
  ##################################

  elif node.type == "void":
    write("void")
    write("(")


  #
  # OPEN: ARRAY
  ##################################

  elif node.type == "array":
    write("[")

    if node.hasChildren(True):
      space(False)


  #
  # OPEN: PARAMS
  ##################################

  elif node.type == "params":
    noline()
    write("(")








  #
  # OPEN: CASE
  ##################################

  elif node.type == "case":
    if pretty:
      # force double new lines
      if not node.isFirstChild() and not node.getPreviousSibling(True).type == "case":
        sep()

      minus()
      line()

    write("case")
    space()


  #
  # OPEN: DEFAULT
  ##################################

  elif node.type == "default":
    if pretty:
      minus()

      # force double new lines
      if not node.getPreviousSibling(True).type == "case":
        sep()

    write("default")
    write(":")

    if pretty:
      plus()
      line()






  #
  # OPEN: TRY
  ##################################

  elif node.type == "switch":
    # Additional new line before each switch/try
    if not node.isFirstChild(True) and not node.getChild("commentsBefore", False):
      prev = node.getPreviousSibling(False, True)

      # No separation after case statements
      if prev != None and prev.type in [ "case", "default" ]:
        pass
      else:
        sep()

    if node.get("switchType") == "catch":
      write("try")
    elif node.get("switchType") == "case":
      write("switch")


  #
  # OPEN: CATCH
  ##################################

  elif node.type == "catch":
    if pretty:
      # If this statement block or the previous try were not complex, be not complex here, too
      if not node.getChild("statement").getChild("block").isComplex() and not node.parent.getChild("statement").getChild("block").isComplex():
        noline()
        space()

    write("catch")







  #
  # OPEN: MAP
  ##################################

  elif node.type == "map":
    par = node.parent

    if pretty:
      postProcessMap(node)

    if pretty:
      # No break before return statement
      if node.hasParent() and node.parent.type == "expression" and node.parent.parent.type == "return":
        pass

      elif node.isComplex():
        line()

    write("{")

    if pretty:
      if node.isComplex():
        line()
        plus()

      elif node.hasChildren(True):
        space()


  #
  # OPEN: KEYVALUE
  ##################################

  elif node.type == "keyvalue":
    keyString = node.get("key")
    keyQuote = node.get("quote", False)

    if keyQuote != None:
      # print "USE QUOTATION"
      if keyQuote == "doublequotes":
        keyString = '"' + keyString + '"'
      else:
        keyString = "'" + keyString + "'"

    elif keyString in config.JSPROTECTED or not KEY.match(keyString):
      print "Warning: Auto protect key: %s" % keyString
      keyString = "\"" + keyString + "\""

    if pretty and not node.isFirstChild(True) and not node.hasChild("commentsBefore") and node.getChild("value").isComplex():
      sep()

    write(keyString)
    space(False)

    # Fill with spaces
    # Do this only if the parent is complex (many entries)
    # But not if the value itself is complex
    if pretty and node.parent.isComplex() and node.parent.get("alignValues"):
      write(" " * (node.parent.get("maxKeyLength") - len(keyString)))

    write(":")
    space(False)







  #
  # OPEN: BLOCK
  ##################################

  elif node.type == "block":
    if pretty:
      if node.isComplex():
        line()
      else:
        space()

    write("{")

    if pretty:
      if node.hasChildren():
        plus()
        line()


  #
  # OPEN: LOOP
  ##################################

  elif node.type == "loop":
    # Additional new line before each loop
    if not node.isFirstChild(True) and not node.getChild("commentsBefore", False):
      prev = node.getPreviousSibling(False, True)

      # No separation after case statements
      if prev != None and prev.type in [ "case", "default" ]:
        pass
      elif node.hasChild("elseStatement") or node.getChild("statement").hasBlockChildren():
        sep()
      else:
        line()

    loopType = node.get("loopType")

    if loopType == "IF":
      write("if")
      space(False)

    elif loopType == "WHILE":
      write("while")
      space(False)

    elif loopType == "FOR":
      write("for")
      space(False)

    elif loopType == "DO":
      write("do")
      space(False)

    elif loopType == "WITH":
      write("with")
      space(False)

    else:
      print "Warning: Unknown loop type: %s" % loopType



  #
  # OPEN: ELSE
  ##################################

  elif node.type == "elseStatement":
    if node.hasChild("commentsBefore"):
      pass

    elif pretty:
      if not node.hasChild("block") and not node.hasChild("loop"):
        pass

      elif not node.isComplex():
        noline()
        space()

    write("else")

    # This is a elseStatement without a block around (a set of {})
    if not node.hasChild("block"):
      space()


  #
  # OPEN: EXPRESSION
  ##################################

  elif node.type == "expression":
    if node.parent.type == "loop":
      loopType = node.parent.get("loopType")

      # only do-while loops
      if loopType == "DO":
        if pretty:
          stmnt = node.parent.getChild("statement")
          compact = stmnt.hasChild("block") and not stmnt.getChild("block").isComplex()

          if compact:
            noline()
            space()

        write("while")

        if pretty:
          space()

      # open expression block of IF/WHILE/DO-WHILE/FOR statements
      write("(")

    elif node.parent.type == "catch":
      # open expression block of CATCH statement
      write("(")

    elif node.parent.type == "switch" and node.parent.get("switchType") == "case":
      # open expression block of SWITCH statement
      write("(")


  #
  # OPEN: FIRST
  ##################################

  elif node.type == "first":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      write("(")

    # operation
    elif node.parent.type == "operation":
      # operation (var a = -1)
      if node.parent.get("left", False) == True:
        compileToken(node.parent.get("operator"), True)



  #
  # OPEN: SECOND
  ##################################

  elif node.type == "second":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      if not node.parent.hasChild("first"):
        write("(;")

    # operation
    elif node.parent.type == "operation":
      if node.isComplex():
        # (?: hook operation)
        if node.parent.get("operator") == "HOOK":
          sep()
        else:
          line()





  #
  # OPEN: THIRD
  ##################################

  elif node.type == "third":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      if not node.parent.hasChild("second"):
        if node.parent.hasChild("first"):
          write(";")
          space(False)
        else:
          write("(;;")

    # operation
    elif node.parent.type == "operation":
      # (?: hook operation)
      if node.parent.get("operator") == "HOOK":
        if node.isComplex():
          sep()


  #
  # OPEN: STATEMENT
  ##################################

  elif node.type == "statement":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      if node.parent.get("forVariant") == "iter":
        if not node.parent.hasChild("first") and not node.parent.hasChild("second") and not node.parent.hasChild("third"):
          write("(;;");

        elif not node.parent.hasChild("second") and not node.parent.hasChild("third"):
          write(";")

      write(")")

      if not node.hasChild("block"):
        space(False)













  #####################################################################################################################
  # Children content
  #####################################################################################################################

  if node.hasChildren():
    for child in node.children:
      if not node.type in [ "commentsBefore", "commentsAfter" ]:
        compileNode(child)









  #####################################################################################################################
  # Closing node
  #####################################################################################################################

  #
  # CLOSE: IDENTIFIER
  ##################################

  if node.type == "identifier":
    if node.hasParent() and node.parent.type == "variable" and not node.isLastChild(True):
      write(".")
    elif node.hasParent() and node.parent.type == "label":
      write(":")


  #
  # CLOSE: ACCESSOR
  ##################################

  elif node.type == "accessor":
    if node.hasParent() and node.parent.type == "variable" and not node.isLastChild(True):
      write(".")


  #
  # CLOSE: KEYVALUE
  ##################################

  elif node.type == "keyvalue":
    if node.hasParent() and node.parent.type == "map" and not node.isLastChild(True):
      noline()
      write(",")

      if pretty:
        commentNode(node)

        if node.getChild("value").isComplex():
          sep()
        elif node.parent.isComplex():
          line()
        else:
          space()


  #
  # CLOSE: DEFINITION
  ##################################

  elif node.type == "definition":
    if node.hasParent() and node.parent.type == "definitionList" and not node.isLastChild(True):
      write(",")

      if pretty:
        commentNode(node)

        if node.hasComplexChildren():
          line()
        else:
          space()


  #
  # CLOSE: LEFT
  ##################################

  elif node.type == "left":
    if node.hasParent() and node.parent.type == "assignment":
      oper = node.parent.get("operator", False)

      if node.parent.parent.type == "statementList":
        realNode = node.parent.parent
      else:
        realNode = node.parent

      # be compact in for-loops
      compact = realNode.hasParent() and realNode.parent.type in [ "first", "second", "third" ] and realNode.parent.parent.type == "loop" and realNode.parent.parent.get("loopType") == "FOR"
      compileToken(oper, compact)






  #
  # CLOSE: KEY
  ##################################

  elif node.type == "key":
    if node.hasParent() and node.parent.type == "accessor":
      write("]")


  #
  # CLOSE: GROUP
  ##################################

  elif node.type == "group":
    if node.getChildrenLength(True) == 1:
      noline()

    write(")")


  #
  # CLOSE: VOID
  ##################################

  elif node.type == "void":
    if node.getChildrenLength(True) == 1:
      noline()

    write(")")


  #
  # CLOSE: ARRAY
  ##################################

  elif node.type == "array":
    if node.hasChildren(True):
      space(False)

    write("]")


  #
  # CLOSE: PARAMS
  ##################################

  elif node.type == "params":
    write(")")


  #
  # CLOSE: MAP
  ##################################

  elif node.type == "map":
    if pretty:
      if node.isComplex():
        line()
        minus()

      elif node.hasChildren(True):
        space()

    write("}")






  #
  # CLOSE: SWITCH
  ##################################

  elif node.type == "switch":
    if node.get("switchType") == "case":
      if pretty:
        minus()
        minus()
        line()

      write("}")

      if pretty:
        commentNode(node)
        line()

    # Force a additinal line feed after each switch/try
    if pretty and not node.isLastChild():
      sep()


  #
  # CLOSE: CASE
  ##################################

  elif node.type == "case":
    write(":")

    if pretty:
      commentNode(node)
      plus()
      line()








  #
  # CLOSE: BLOCK
  ##################################

  elif node.type == "block":
    if pretty and node.hasChildren():
      minus()
      line()

    write("}")

    if pretty:
      commentNode(node)

      if node.hasChildren():
        # Newline afterwards
        if node.parent.type == "body" and node.parent.parent.type == "function":

          # But only when this isn't a function block inside a assignment
          if node.parent.parent.parent.type in [ "right", "params" ]:
            pass

          elif node.parent.parent.parent.type == "value" and node.parent.parent.parent.parent.type == "keyvalue":
            pass

          else:
            line()

        else:
          line()


  #
  # CLOSE: LOOP
  ##################################

  elif node.type == "loop":
    if node.get("loopType") == "DO":
      semicolon()

    if pretty:
      commentNode(node)

      # Force a additinal line feed after each loop
      if not node.isLastChild():
        if node.hasChild("elseStatement"):
          sep()
        elif node.getChild("statement").hasBlockChildren():
          sep()
        else:
          line()


  #
  # CLOSE: FUNCTION
  ##################################

  elif node.type == "function":
    if pretty:
      commentNode(node)

      if not node.isLastChild() and node.hasParent() and node.parent.type in [ "block", "file" ]:
        sep()


  #
  # CLOSE: EXPRESSION
  ##################################

  elif node.type == "expression":
    if node.parent.type == "loop":
      write(")")

      # e.g. a if-construct without a block {}
      if node.parent.getChild("statement").hasChild("block"):
        pass

      elif node.parent.type == "loop" and node.parent.get("loopType") == "DO":
        pass

      else:
        space(False)

    elif node.parent.type == "catch":
      write(")")

    elif node.parent.type == "switch" and node.parent.get("switchType") == "case":
      write(")")

      if pretty:
        commentNode(node)
        line()

      write("{")

      if pretty:
        plus()
        plus()


  #
  # CLOSE: FIRST
  ##################################

  elif node.type == "first":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      if node.parent.get("forVariant") == "iter":
        write(";")

        if node.parent.hasChild("second"):
          space(False)

    # operation
    elif node.parent.type == "operation" and node.parent.get("left", False) != True:
      oper = node.parent.get("operator")

      if node.parent.parent.type == "statementList":
        realNode = node.parent.parent
      else:
        realNode = node.parent

      compact = realNode.hasParent() and realNode.parent.type in [ "first", "second", "third" ] and realNode.parent.parent.type == "loop" and realNode.parent.parent.get("loopType") == "FOR"
      compileToken(oper, compact)


  #
  # CLOSE: SECOND
  ##################################

  elif node.type == "second":
    # for loop
    if node.parent.type == "loop" and node.parent.get("loopType") == "FOR":
      write(";")

      if node.parent.hasChild("third"):
        space(False)

    # operation
    elif node.parent.type == "operation":
      # (?: hook operation)
      if node.parent.get("operator") == "HOOK":
        noline()
        space(False)
        write(":")
        space(False)









  #
  # CLOSE: OTHER
  ##################################

  if node.hasParent() and not node.type in [ "comment", "commentsBefore", "commentsAfter" ]:

    # Add comma dividers between statements in these parents
    if node.parent.type in [ "array", "params", "statementList" ]:
      if not node.isLastChild(True):
        write(",")

        if pretty:
          commentNode(node)

          if node.isComplex():
            line()
          else:
            space()

    # Semicolon handling
    elif node.type in [ "block", "assignment", "call", "operation", "definitionList", "return", "break", "continue", "delete", "accessor", "instantiation", "throw", "variable" ]:

      # Default semicolon handling
      if node.parent.type in [ "block", "file" ]:
        semicolon()

        if pretty:
          commentNode(node)
          line()

          if node.isComplex() and not node.isLastChild():
            sep()

      # Special handling for switch statements
      elif node.parent.type == "statement" and node.parent.parent.type == "switch" and node.parent.parent.get("switchType") == "case":
        semicolon()

        if pretty:
          commentNode(node)
          line()

          if node.isComplex() and not node.isLastChild():
            sep()

      # Special handling for loops (e.g. if) without blocks {}
      elif node.parent.type in [ "statement", "elseStatement" ] and not node.parent.hasChild("block") and node.parent.parent.type == "loop":
        semicolon()

        if pretty:
          commentNode(node)
          line()

          if node.isComplex() and not node.isLastChild():
            sep()


  #
  # CLOSE: OTHER
  ##################################

  if pretty:
    # Rest of the after comments (not inserted previously)
    commentNode(node)











def main():
  parser = optparse.OptionParser()

  parser.add_option("-w", "--write", action="store_true", dest="write", default=False, help="Writes file to incoming fileName + EXTENSION.")
  parser.add_option("-e", "--extension", dest="extension", metavar="EXTENSION", help="The EXTENSION to use", default=".compiled")
  parser.add_option("-c", "--compress", action="store_true", dest="compress", help="Enable compression", default=False)
  parser.add_option("--optimize-variables", action="store_true", dest="optimizeVariables", default=False, help="Optimize variables. Reducing size.")
  parser.add_option("--encoding", dest="encoding", default="utf-8", metavar="ENCODING", help="Defines the encoding expected for input files.")

  (options, args) = parser.parse_args()

  if len(args) == 0:
    print "Needs one or more arguments (files) to compile!"
    sys.exit(1)

  for fileName in args:
    if options.write:
      print "Compiling %s => %s%s" % (fileName, fileName, options.extension)
    else:
      print "Compiling %s => stdout" % fileName

    restree = treegenerator.createSyntaxTree(tokenizer.parseFile(fileName, "", options.encoding))

    if options.optimizeVariables:
      variableoptimizer.search(restree, [], 0, "$")

    compiledString = compile(restree, not options.compress)
    if options.write:
      filetool.save(fileName + options.extension, compiledString)

    else:
      try:
        print compiledString

      except UnicodeEncodeError:
        print "  * Could not encode result to ascii. Use '-w' instead."
        sys.exit(1)



if __name__ == '__main__':
  try:
    main()

  except KeyboardInterrupt:
    print
    print "  * Keyboard Interrupt"
    sys.exit(1)
