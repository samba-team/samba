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
#    * Andreas Ecker (ecker)
#    * Fabian Jakobs (fjakobs)
#
################################################################################

import sys, os, re, optparse
import tree, treegenerator, tokenizer, comment



########################################################################################
#
#  MAIN
#
########################################################################################

class DocException (Exception):
  def __init__ (self, msg, syntaxItem):
    Exception.__init__(self, msg)
    self.node = syntaxItem



def createDoc(syntaxTree, docTree = None):
  if not docTree:
    docTree = tree.Node("doctree")

  try:
    currClassNode = None
    if not syntaxTree.hasChildren():
      return docTree

    for item in syntaxTree.children:
      if item.type == "assignment":
        leftItem = item.getFirstListChild("left")
        rightItem = item.getFirstListChild("right")
        if leftItem.type == "variable":
          if currClassNode and len(leftItem.children) == 3 and leftItem.children[0].get("name") == "qx":

            if leftItem.children[1].get("name") == "Proto" and rightItem.type == "function":
              # It's a method definition
              handleMethodDefinitionOld(item, False, currClassNode)

            elif leftItem.children[1].get("name") == "Class":
              if rightItem.type == "function":
                handleMethodDefinitionOld(item, True, currClassNode)

              elif leftItem.children[2].get("name").isupper():
                handleConstantDefinition(item, currClassNode)

          elif currClassNode and assembleVariable(leftItem).startswith(currClassNode.get("fullName")):
            # This is definition of the type "mypackage.MyClass.bla = ..."
            if rightItem.type == "function":
              handleMethodDefinitionOld(item, True, currClassNode)

            elif leftItem.children[len(leftItem.children) - 1].get("name").isupper():
              handleConstantDefinition(item, currClassNode)

      elif item.type == "call":
        operand = item.getChild("operand", False)
        if operand:
          var = operand.getChild("variable", False)

          # qooxdoo < 0.7 (DEPRECATED)
          if var and len(var.children) == 3 and var.children[0].get("name") == "qx" and var.children[1].get("name") == "OO":
            methodName = var.children[2].get("name")

            if methodName == "defineClass":
              currClassNode = handleClassDefinitionOld(docTree, item)

            elif methodName in [ "addProperty", "addFastProperty" ]:
              # these are private and should be marked if listed, otherwise just hide them (wpbasti)
              #or methodName == "addCachedProperty" or methodName == "changeProperty":
              handlePropertyDefinitionOld(item, currClassNode)

          # qooxdoo >= 0.7
          elif var and len(var.children) == 3 and var.children[0].get("name") == "qx" and var.children[1].get("name") in [ "Class", "Clazz", "Locale", "Interface", "Mixin" ] and var.children[2].get("name") == "define":
            currClassNode = handleClassDefinition(docTree, item, var.children[1].get("name").lower())


  except Exception:
    exc = sys.exc_info()[1]
    msg = ""

    if hasattr(exc, "node"):
      (line, column) = getLineAndColumnFromSyntaxItem(exc.node)
      file = getFileFromSyntaxItem(exc.node)
      if line != None or file != None:
        msg = str(exc) + "\n      " + str(file) + ", Line: " + str(line) + ", Column: " + str(column)

    if msg == "":
      raise exc

    else:
      print
      print "    - Failed: %s" % msg
      sys.exit(1)

  return docTree










########################################################################################
#
#  COMPATIBLE TO 0.7 STYLE ONLY!
#
########################################################################################

def handleClassDefinition(docTree, item, variant):
  params = item.getChild("params")

  className = params.children[0].get("value")
  classMap = params.children[1]
  classNode = getClassNode(docTree, className)

  #print className

  try:
      children = classMap.children
  except AttributeError:
      return

  for keyvalueItem in children:
    key = keyvalueItem.get("key")
    valueItem = keyvalueItem.getChild("value").getFirstChild()

    # print "KEY: %s = %s" % (key, valueItem.type)

    if key == "extend":
      if variant in [ "class", "clazz" ]:
        superClassName = assembleVariable(valueItem)
        superClassNode = getClassNode(docTree, superClassName)
        childClasses = superClassNode.get("childClasses", False)

        if childClasses:
          childClasses += "," + className
        else:
          childClasses = className

        superClassNode.set("childClasses", childClasses)

        classNode.set("superClass", superClassName)

      elif variant == "interface":
        pass

      elif variant == "mixin":
        pass

    elif key == "include":
      handleMixins(valueItem, classNode)

    elif key == "implement":
      handleInterfaces(valueItem, classNode)

    elif key == "init":
      handleConstructor(valueItem, classNode)

    elif key == "statics":
      handleStatics(valueItem, classNode)

    elif key == "properties":
    	handleProperties(valueItem, classNode)

    elif key == "members":
      handleMembers(valueItem, classNode)

def handleMixins(item, classNode):
  #print "  - Found Mixin"
  pass

def handleInterfaces(item, classNode):
  #print "  - Found Interface"
  pass

def handleConstructor(item, classNode):
  #print "  - Found Constructor"
  pass

def handleStatics(item, classNode):
  if item.hasChildren():
    for keyvalue in item.children:
      key = keyvalue.get("key")
      value = keyvalue.getFirstChild(True, True).getFirstChild(True, True)
      commentAttributes = comment.parseNode(keyvalue)

      # print "  - Found Static: %s = %s" % (key, value.type)

      # Function
      if value.type == "function":
        node = handleFunction(value, commentAttributes, classNode)
        node.set("name", key)
        node.set("isStatic", True)

        classNode.addListChild("methods-static", node)

      # Constant
      elif key.isupper():
        handleConstantDefinition(keyvalue, classNode)

def handleProperties(item, classNode):
  if item.hasChildren():
    for keyvalue in item.children:
      key = keyvalue.get("key")
      value = keyvalue.getFirstChild(True, True).getFirstChild(True, True)
      # print "  - Found Property: %s" % key

      # TODO: New handling for new properties needed
      handlePropertyDefinitionOldCommon(keyvalue, classNode, key, value)

def handleMembers(item, classNode):
  if item.hasChildren():
    for keyvalue in item.children:
      key = keyvalue.get("key")
      value = keyvalue.getFirstChild(True, True).getFirstChild(True, True)
      commentAttributes = comment.parseNode(keyvalue)

      # print "  - Found Member: %s = %s" % (key, value.type)

      # Function
      if value.type == "function":

        node = handleFunction(value, commentAttributes, classNode)
        node.set("name", key)

        classNode.addListChild("methods", node)






########################################################################################
#
#  COMPATIBLE TO 0.6 STYLE ONLY!
#
########################################################################################

def handleClassDefinitionOld(docTree, item):
  params = item.getChild("params")

  paramsLen = len(params.children);
  if paramsLen == 1:
    superClassName = "Object"
    ctorItem = None
  elif paramsLen == 2:
    superClassName = "Object"
    ctorItem = params.children[1]
  elif paramsLen == 3:
    superClassName = assembleVariable(params.children[1])
    ctorItem = params.children[2]
  else:
    raise DocException("defineClass call has more than three parameters: " + str(len(params.children)), item)

  className = params.children[0].get("value")
  classNode = getClassNode(docTree, className)
  
  if superClassName != "Object":
    superClassNode = getClassNode(docTree, superClassName)
    childClasses = superClassNode.get("childClasses", False)
    if childClasses:
      childClasses += "," + className
    else:
      childClasses = className
    superClassNode.set("childClasses", childClasses)

    classNode.set("superClass", superClassName)

  commentAttributes = comment.parseNode(item)
  
  for attrib in commentAttributes:
    if attrib["category"] == "event":
      # Add the event
      if comment.attribHas(attrib, "name") and comment.attribHas(attrib, "type"):
        addEventNode(classNode, item, attrib);
      else:
        addError(classNode, "Documentation contains malformed event attribute.", item)
    elif attrib["category"] == "description":
      if attrib.has_key("text"):
        descNode = tree.Node("desc").set("text", attrib["text"])
        classNode.addChild(descNode)

  # Add the constructor
  if ctorItem and ctorItem.type == "function":
    ctor = handleFunction(ctorItem, commentAttributes, classNode)
    ctor.set("isCtor", True)
    classNode.addListChild("constructor", ctor)

    # Check for methods defined in the constructor
    # (for method definition style that supports real private methods)
    ctorBlock = ctorItem.getChild("body").getChild("block")

    if ctorBlock.hasChildren():
      for item in ctorBlock.children:
        if item.type == "assignment":
          leftItem = item.getFirstListChild("left")
          rightItem = item.getFirstListChild("right")

          # It's a method definition
          if leftItem.type == "variable" and len(leftItem.children) == 2 and (leftItem.children[0].get("name") == "this" or leftItem.children[0].get("name") == "self") and rightItem.type == "function":
            handleMethodDefinitionOld(item, False, classNode)

  elif ctorItem and ctorItem.type == "map":
    for keyvalueItem in ctorItem.children:
      if keyvalueItem.type == "keyvalue":
        valueItem = keyvalueItem.getChild("value").getFirstChild()
        if (valueItem.type == "function"):
          handleMethodDefinitionOld(keyvalueItem, True, classNode)
        else:
          handleConstantDefinition(keyvalueItem, classNode)

  return classNode

def handlePropertyDefinitionOld(item, classNode):
  paramsMap = item.getChild("params").getChild("map")
  propertyName = paramsMap.getChildByAttribute("key", "name").getChild("value").getChild("constant").get("value")

  handlePropertyDefinitionOldCommon(item, classNode, propertyName, paramsMap)

def handlePropertyDefinitionOldCommon(item, classNode, propertyName, paramsMap):
  node = tree.Node("property")
  node.set("name", propertyName)

  propType = paramsMap.getChildByAttribute("key", "type", False)
  if propType:
    node.set("type", getType(propType.getChild("value").getFirstChild()))

  allowNull = paramsMap.getChildByAttribute("key", "allowNull", False)
  if allowNull:
    node.set("allowNull", allowNull.getChild("value").getChild("constant").get("value"))

  defaultValue = paramsMap.getChildByAttribute("key", "defaultValue", False)
  if defaultValue:
    node.set("defaultValue", getValue(defaultValue.getFirstListChild("value")))

  getAlias = paramsMap.getChildByAttribute("key", "getAlias", False)
  if getAlias:
    node.set("getAlias", getAlias.getChild("value").getChild("constant").get("value"))

  setAlias = paramsMap.getChildByAttribute("key", "setAlias", False)
  if setAlias:
    node.set("setAlias", setAlias.getChild("value").getChild("constant").get("value"))

  unitDetection = paramsMap.getChildByAttribute("key", "unitDetection", False)
  if unitDetection:
    node.set("unitDetection", unitDetection.getChild("value").getChild("constant").get("value"))

  instance = paramsMap.getChildByAttribute("key", "instance", False)
  if instance:
    node.set("instance", instance.getChild("value").getChild("constant").get("value"))

  classname = paramsMap.getChildByAttribute("key", "classname", False)
  if classname:
    node.set("classname", classname.getChild("value").getChild("constant").get("value"))

  possibleValues = paramsMap.getChildByAttribute("key", "possibleValues", False)
  if possibleValues:
    array = possibleValues.getChild("value").getChild("array")
    values = ""
    for arrayItem in array.children:
      if len(values) != 0:
        values += ", "
      values += getValue(arrayItem)
    node.set("possibleValues", values)

  # If the description has a type specified then take this type
  # (and not the one extracted from the paramsMap)
  commentAttributes = comment.parseNode(item)
  addTypeInfo(node, comment.getAttrib(commentAttributes, "description"), item)

  classNode.addListChild("properties", node)

def handleMethodDefinitionOld(item, isStatic, classNode):
  if item.type == "assignment":
    # This is a "normal" method definition
    leftItem = item.getFirstListChild("left")
    name = leftItem.children[len(leftItem.children) - 1].get("name")
    functionItem = item.getFirstListChild("right")
  elif item.type == "keyvalue":
    # This is a method definition of a map-style class (like qx.Const)
    name = item.get("key")
    functionItem = item.getFirstListChild("value")

  commentAttributes = comment.parseNode(item)

  node = handleFunction(functionItem, commentAttributes, classNode)
  node.set("name", name)

  isPublic = name[0] != "_"
  listName = "methods"
  if isStatic:
    node.set("isStatic", True)
    listName += "-static"

  classNode.addListChild(listName, node)








########################################################################################
#
#  COMPATIBLE TO BOTH, 0.6 and 0.7 style
#
########################################################################################

def handleConstantDefinition(item, classNode):
  if (item.type == "assignment"):
    # This is a "normal" constant definition
    leftItem = item.getFirstListChild("left")
    name = leftItem.children[len(leftItem.children) - 1].get("name")
    valueNode = item.getChild("right")
  elif (item.type == "keyvalue"):
    # This is a constant definition of a map-style class (like qx.Const)
    name = item.get("key")
    valueNode = item.getChild("value")

  if not name.isupper():
    return
  
  node = tree.Node("constant")      
  node.set("name", name)
  
  value = None
  if valueNode.hasChild("constant"):
      node.set("value", valueNode.getChild("constant").get("value"))
      node.set("type", valueNode.getChild("constant").get("constantType").capitalize())

  commentAttributes = comment.parseNode(item)
  description = comment.getAttrib(commentAttributes, "description")
  addTypeInfo(node, description, item)

  classNode.addListChild("constants", node)

def handleFunction(funcItem, commentAttributes, classNode):
  if funcItem.type != "function":
    raise DocException("'funcItem' is no function", funcItem)

  node = tree.Node("method")

  # Read the parameters
  params = funcItem.getChild("params", False)
  if params and params.hasChildren():
    for param in params.children:
      paramNode = tree.Node("param")
      paramNode.set("name", param.getFirstChild().get("name"))
      node.addListChild("params", paramNode)

  # Check whether the function is abstract
  bodyBlockItem = funcItem.getChild("body").getFirstChild();
  if bodyBlockItem.type == "block" and bodyBlockItem.hasChildren():
    firstStatement = bodyBlockItem.children[0];
    if firstStatement.type == "throw":
      # The first statement of the function is a throw statement
      # -> The function is abstract
      node.set("isAbstract", True)

  if len(commentAttributes) == 0:
    addError(node, "Documentation is missing.", funcItem)
    return node

  # Read all description, param and return attributes
  for attrib in commentAttributes:
    # Add description
    if attrib["category"] == "description":
      if attrib.has_key("text"):
        descNode = tree.Node("desc").set("text", attrib["text"])
        node.addChild(descNode)

    elif attrib["category"] == "see":
      if not attrib.has_key("name"):
        raise DocException("Missing target for see.", funcItem)

      seeNode = tree.Node("see").set("name", attrib["name"])
      node.addChild(seeNode)

    elif attrib["category"] == "param":
      if not attrib.has_key("name"):
        raise DocException("Missing name of parameter.", funcItem)

      # Find the matching param node
      paramName = attrib["name"]
      paramNode = node.getListChildByAttribute("params", "name", paramName, False)

      if not paramNode:
        addError(node, "Contains information for a non-existing parameter <code>%s</code>." % paramName, funcItem)
        continue

      addTypeInfo(paramNode, attrib, funcItem)

    elif attrib["category"] == "return":
      returnNode = tree.Node("return")
      node.addChild(returnNode)

      addTypeInfo(returnNode, attrib, funcItem)

  # Check for documentation errors
  # Check whether all parameters have been documented
  if node.hasChild("params"):
    paramsListNode = node.getChild("params");
    for paramNode in paramsListNode.children:
      if not paramNode.getChild("desc", False):
        addError(node, "Parameter %s is not documented." % paramNode.get("name"), funcItem)

  return node










########################################################################################
#
#  COMMON STUFF
#
#######################################################################################


def variableIsClassName(varItem):
  length = len(varItem.children)
  for i in range(length):
    varChild = varItem.children[i]
    if not varChild.type == "identifier":
      return False
    if i < length - 1:
      # This is not the last identifier -> It must a package (= lowercase)
      if not varChild.get("name").islower():
        return False
    else:
      # This is the last identifier -> It must the class name (= first letter uppercase)
      if not varChild.get("name")[0].isupper():
        return False
  return True



def assembleVariable(variableItem):
  if variableItem.type != "variable":
    raise DocException("'variableItem' is no variable", variableItem)

  assembled = ""
  for child in variableItem.children:
    if len(assembled) != 0:
      assembled += "."
    assembled += child.get("name")

  return assembled



def getValue(item):
  value = None
  if item.type == "constant":
    if item.get("constantType") == "string":
      value = '"' + item.get("value") + '"'
    else:
      value = item.get("value")
  elif item.type == "variable":
    value = assembleVariable(item)
  elif item.type == "operation" and item.get("operator") == "SUB":
    # E.g. "-1" or "-Infinity"
    value = "-" + getValue(item.getChild("first").getFirstChild())
  if value == None:
    value = "[Unsupported item type: " + item.type + "]"

  return value



def addTypeInfo(node, commentAttrib=None, item=None):
  if commentAttrib == None:
    if node.type == "constant" and node.get("value", False):
        pass
    
    elif node.type == "param":
      addError(node, "Parameter <code>%s</code> in not documented." % commentAttrib.get("name"), item)

    elif node.type == "return":
      addError(node, "Return value is not documented.", item)

    else:
      addError(node, "Documentation is missing.", item)

    return

  # add description
  if commentAttrib.has_key("text"):
    node.addChild(tree.Node("desc").set("text", commentAttrib["text"]))

  # add types
  if commentAttrib.has_key("type"):
    typesNode = tree.Node("types")
    node.addChild(typesNode)

    for item in commentAttrib["type"]:
      itemNode = tree.Node("entry")
      typesNode.addChild(itemNode)

      itemNode.set("type", item["type"])

      if item["dimensions"] != 0:
        itemNode.set("dimensions", item["dimensions"])

  # add default value
  if commentAttrib.has_key("default"):
    defaultValue = commentAttrib["default"]
    if defaultValue != None:
      # print "defaultValue: %s" % defaultValue
      node.set("defaultValue", defaultValue)



def addEventNode(classNode, classItem, commentAttrib):
  node = tree.Node("event")

  node.set("name", commentAttrib["name"])

  if commentAttrib.has_key("text"):
    node.addChild(tree.Node("desc").set("text", commentAttrib["text"]))

  # add types
  if commentAttrib.has_key("type"):
    typesNode = tree.Node("types")
    node.addChild(typesNode)

    for item in commentAttrib["type"]:
      itemNode = tree.Node("entry")
      typesNode.addChild(itemNode)

      itemNode.set("type", item["type"])

      if item["dimensions"] != 0:
        itemNode.set("dimensions", item["dimensions"])

  classNode.addListChild("events", node)



def addError(node, msg, syntaxItem):
  # print ">>> %s" % msg

  errorNode = tree.Node("error")
  errorNode.set("msg", msg)

  (line, column) = getLineAndColumnFromSyntaxItem(syntaxItem)
  if line:
    errorNode.set("line", line)

    if column:
      errorNode.set("column", column)

  node.addListChild("errors", errorNode)
  node.set("hasError", True)



def getLineAndColumnFromSyntaxItem(syntaxItem):
  line = None
  column = None

  while line == None and column == None and syntaxItem:
    line = syntaxItem.get("line", False)
    column = syntaxItem.get("column", False)

    if syntaxItem.hasParent():
      syntaxItem = syntaxItem.parent
    else:
      syntaxItem = None

  return line, column


def getFileFromSyntaxItem(syntaxItem):
  file = None
  while file == None and syntaxItem:
    file = syntaxItem.get("file", False)
    if hasattr(syntaxItem, "parent"):
      syntaxItem = syntaxItem.parent
    else:
      syntaxItem = None
  return file


def getType(item):
  if item.type == "constant" and item.get("constantType") == "string":
    val = item.get("value").capitalize()
    return val

  else:
    raise DocException("Can't gess type. type is neither string nor variable: " + item.type, item)


def getClassNode(docTree, className):
  splits = className.split(".")

  currPackage = docTree
  length = len(splits)
  for i in range(length):
    split = splits[i]

    if (i < length - 1):
      # This is a package name -> Get the right package
      childPackage = currPackage.getListChildByAttribute("packages", "name", split, False)
      if not childPackage:
        childPackageName = ".".join(splits[:-(length-i-1)])

        # The package does not exist -> Create it
        childPackage = tree.Node("package")
        childPackage.set("name", split)
        childPackage.set("fullName", childPackageName)
        childPackage.set("packageName", childPackageName.replace("." + split, ""))

        currPackage.addListChild("packages", childPackage)

      # Update current package
      currPackage = childPackage

    else:
      # This is a class name -> Get the right class
      classNode = currPackage.getListChildByAttribute("classes", "name", split, False)
      if not classNode:
        # The class does not exist -> Create it
        classNode = tree.Node("class")
        classNode.set("name", split)
        classNode.set("fullName", className)
        classNode.set("packageName", className.replace("." + split, ""))
        currPackage.addListChild("classes", classNode)

      return classNode



def postWorkPackage(docTree, packageNode):
  childHasError = False

  packages = packageNode.getChild("packages", False)
  if packages:
    packages.children.sort(nameComparator)
    for node in packages.children:
      hasError = postWorkPackage(docTree, node)
      if hasError:
        childHasError = True

  classes = packageNode.getChild("classes", False)
  if classes:
    classes.children.sort(nameComparator)
    for node in classes.children:
      hasError = postWorkClass(docTree, node)
      if hasError:
        childHasError = True

  if childHasError:
    packageNode.set("hasWarning", True)

  return childHasError



def postWorkClass(docTree, classNode):
  # Sort child classes
  childClasses = classNode.get("childClasses", False)
  if childClasses:
    classArr = childClasses.split(",")
    classArr.sort()
    childClasses = ",".join(classArr)
    classNode.set("childClasses", childClasses)

  # Remove the property-modifier-methods
  removePropertyModifiers(classNode)

  # Mark overridden items
  postWorkItemList(docTree, classNode, "properties", True)
  postWorkItemList(docTree, classNode, "events", False)
  postWorkItemList(docTree, classNode, "methods", True)
  postWorkItemList(docTree, classNode, "methods-static", False)

  # Check whether the class is static
  superClassName = classNode.get("superClass", False)
  if (superClassName == None or superClassName == "qx.core.Object") \
    and classNode.getChild("properties", False) == None \
    and classNode.getChild("methods", False) == None:
    # This class is static
    classNode.set("isStatic", True)

  # Check whether the class is abstract
  if isClassAbstract(docTree, classNode, {}):
    classNode.set("isAbstract", True)

  # Check for errors
  childHasError = listHasError(classNode, "constructor") or listHasError(classNode, "properties") \
    or listHasError(classNode, "methods") or listHasError(classNode, "methods-static") \
    or listHasError(classNode, "constants")

  if childHasError:
    classNode.set("hasWarning", True)

  return childHasError



def isClassAbstract(docTree, classNode, visitedMethodNames):
  if containsAbstractMethods(classNode.getChild("methods", False), visitedMethodNames):
    # One of the methods is abstract
    return True

  # No abstract methods found -> Check whether the super class has abstract
  # methods that haven't been overridden
  superClassName = classNode.get("superClass", False)
  if superClassName:
    superClassNode = getClassNode(docTree, superClassName)
    return isClassAbstract(docTree, superClassNode, visitedMethodNames)



def containsAbstractMethods(methodListNode, visitedMethodNames):
  if methodListNode:
    for methodNode in methodListNode.children:
      name = methodNode.get("name")
      if not name in visitedMethodNames:
        visitedMethodNames[name] = True
        if methodNode.get("isAbstract", False):
          return True

  return False



def removePropertyModifiers(classNode):
  propertiesList = classNode.getChild("properties", False)
  methodsList = classNode.getChild("methods", False)
  if propertiesList and methodsList:
    for propNode in propertiesList.children:
      name = propNode.get("name")
      upperName = name[0].upper() + name[1:]

      modifyNode = methodsList.getChildByAttribute("name", "_modify" + upperName, False)
      if modifyNode:
        methodsList.removeChild(modifyNode);

      changeNode = methodsList.getChildByAttribute("name", "_change" + upperName, False)
      if changeNode:
        methodsList.removeChild(changeNode);

      checkNode = methodsList.getChildByAttribute("name", "_check" + upperName, False)
      if checkNode:
        methodsList.removeChild(checkNode);

    if not methodsList.hasChildren():
      classNode.removeChild(methodsList)



def postWorkItemList(docTree, classNode, listName, overridable):
  """Does the post work for a list of properties or methods."""

  # Sort the list
  sortByName(classNode, listName)

  # Post work all items
  listNode = classNode.getChild(listName, False)
  if listNode:
    for itemNode in listNode.children:
      name = itemNode.get("name")

      # Check whether this item is overridden and try to inherit the
      # documentation from the next matching super class
      if overridable:
        superClassName = classNode.get("superClass", False)
        overriddenFound = False
        docFound = (itemNode.getChild("desc", False) != None)
        while superClassName and (not overriddenFound or not docFound):
          superClassNode = getClassNode(docTree, superClassName)
          superItemNode = superClassNode.getListChildByAttribute(listName, "name", name, False)

          if superItemNode:
            if not docFound:
              # This super item has a description
              # -> Check whether the parameters match
              # NOTE: paramsMatch works for properties, too
              #       (Because both compared properties always have no params)
              if paramsMatch(itemNode, superItemNode):
                # The parameters match -> We can use the documentation of the super class
                itemNode.set("docFrom", superClassName)
                docFound = (superItemNode.getChild("desc", False) != None)

                # Remove previously recorded documentation errors from the item
                # (Any documentation errors will be recorded in the super class)
                removeErrors(itemNode)
            if not overriddenFound:
              # This super class has the item defined -> Add a overridden attribute
              itemNode.set("overriddenFrom", superClassName)
              overriddenFound = True

          # Check the next superclass
          superClassName = superClassNode.get("superClass", False)

        if not docFound and itemNode.get("overriddenFrom", False):
          # This item is overridden, but we didn't find any documentation in the
          # super classes -> Add a warning
          itemNode.set("hasWarning", True)



def paramsMatch(methodNode1, methodNode2):
  params1 = methodNode1.getChild("params1", False)
  params2 = methodNode1.getChild("params2", False)

  if params1 == None or params2 == None:
    # One method has no parameters -> The params match if both are None
    return params1 == params2
  elif len(params1.children) != len(params2.children):
    # The param count is different -> The params don't match
    return False
  else:
    for i in range(len(params1.children)):
      par1 = params1.children[i]
      par2 = params2.children[i]
      if (par1.get("name") != par2.get("name")):
        # These parameters don't match
        return False

    # All tests passed
    return True



def removeErrors(node):
  errors = node.getChild("errors", False)
  if errors:
    node.removeChild(errors)
    node.remove("hasError")



def sortByName(node, listName):
  listNode = node.getChild(listName, False)
  if listNode:
    listNode.children.sort(nameComparator)



def nameComparator(node1, node2):
  name1 = node1.get("name").lower()
  name2 = node2.get("name").lower()
  return cmp(name1, name2)



def listHasError(node, listName):
  listNode = node.getChild(listName, False)
  if listNode:
    for childNode in listNode.children:
      if childNode.get("hasError", False):
        return True

  return False
