/*
#module(api)
*/

/**
 * A util class for handling the documentation tree.
 */
qx.OO.defineClass("api.TreeUtil", qx.core.Object,
function () {
  qx.core.Object.call(this);
});


/**
 * Gets the child of a doc node having a certain type.
 *
 * @param docNode {Map} the doc node to get the child of.
 * @param childType {string} the type of the child to get.
 * @return {Map} the wanted child or <code>null</code> if <code>docNode</code>
 *         is <code>null</code> or has no such child.
 */
qx.Class.getChild = function(docNode, childType) {
  if (docNode != null && docNode.children != null) {
    for (var i = 0; i < docNode.children.length; i++) {
      if (docNode.children[i].type == childType) {
        return docNode.children[i];
      }
    }
  }

  return null;
}


/**
 * Gets the child of a doc node having a certain attribute value.
 *
 * @param docNode {Map} the doc node to get the child of.
 * @param attributeName {string} the name of the attribute the wanted child must have.
 * @param attributeValue {string} the value of the attribute the wanted child must have.
 * @return {Map} the wanted child or <code>code</code> if there is no such child.
 */
qx.Class.getChildByAttribute = function(docNode, attributeName, attributeValue) {
  if (docNode.children != null) {
    for (var i = 0; i < docNode.children.length; i++) {
      var node = docNode.children[i];
      if (node.attributes && node.attributes[attributeName] == attributeValue) {
        return node;
      }
    }
  }

  return null;
}


/**
 * Searches the doc node of a item. Only use this method if you don't know the
 * type of the item.
 *
 * @param classNode {Map} the class node the item belongs to.
 * @param itemName {string} the name of the item to search.
 * @return {Map} the doc node of the item or <code>null</code> if the class has
 *         no such item.
 */
qx.Class.getItemDocNode = function(classNode, itemName) {
  var TreeUtil = api.TreeUtil;

  // Go through the item lists and check whether one contains the wanted item
  for (var i = 0; i < TreeUtil.ITEM_LIST_ARR.length; i++) {
    var listNode = TreeUtil.getChild(classNode, TreeUtil.ITEM_LIST_ARR[i]);
    if (listNode) {
      var itemNode = TreeUtil.getChildByAttribute(listNode, "name", itemName);
      if (itemNode) {
        return itemNode;
      }
    }
  }

  // Nothing found
  return null;
}


/**
 * Gets the doc node of a class.
 *
 * @param docTree {Map} the documentation tree.
 * @param className {string} the name of the class.
 * @return {Map} the doc node of the class.
 */
qx.Class.getClassDocNode = function(docTree, className) {
  var splits = className.split(".");
  var currNode = docTree;
  for (var i = 0; i < splits.length && currNode != null; i++) {
    if (i < splits.length - 1) {
      // The current name is a package name
      var packages = this.getChild(currNode, "packages");
      currNode = packages ? this.getChildByAttribute(packages, "name", splits[i]) : null;
    } else {
      // The current name is a class name
      var classes = this.getChild(currNode, "classes");
      currNode = classes ? this.getChildByAttribute(classes, "name", splits[i]) : null;
    }
  }

  return currNode;
}


/**
 * Gets the icon URL of a doc node.
 *
 * @param node {Map} the node to get the icon for.
 * @param inherited {boolean,false} whether the node was inherited.
 * @return {var} the URL of the icon. May be a string or an array of string
 *         (in case of an overlay icon).
 */
qx.Class.getIconUrl = function(node, inherited) {
  var constName;
  switch (node.type) {
    case "package":
      constName = "ICON_PACKAGE";
      break;
    case "class":
      constName = "ICON_CLASS";

      if (node.attributes.isStatic) {
        constName += "_STATIC";
      } else if (node.attributes.isAbstract) {
        constName += "_ABSTRACT";
      }

      break;
    case "property":
      constName = "ICON_PROPERTY";
      break;
    case "event":
      constName = "ICON_EVENT";
      break;
    case "method":
      var isCtor = node.attributes.name == null;
      var isPublic = isCtor || (node.attributes.name.charAt(0) != "_");

      constName = "ICON_METHOD" + (isPublic ? "_PUB" : "_PROT");

      if (isCtor) {
        constName += "_CTOR";
      } else if (node.attributes.isStatic) {
        constName += "_STATIC";
      } else if (node.attributes.isAbstract) {
        constName += "_ABSTRACT";
      }

      break;
    case "constant":
      constName = "ICON_CONSTANT";
      break;
    default: throw new Error("Unknown node type: " + node.type);
  }

  if (inherited) {
    constName += "_INHERITED";
  } else if (node.attributes.overriddenFrom) {
    constName += "_OVERRIDDEN";
  }

  if (node.attributes.hasError) {
    constName += "_ERROR";
  } else if (node.attributes.hasWarning) {
    constName += "_WARN";
  }

  var iconUrl = api.TreeUtil[constName];
  if (iconUrl == null) {
    throw new Error("Unknown img constant: " + constName);
  }
  return iconUrl;
}


/** {string[]} The names of lists containing items. */
qx.Class.ITEM_LIST_ARR = [ "constants", "properties", "methods-pub", "methods-pub",
                        "methods-static-prot", "methods-static-prot" ];


/** {string} The URL of the overlay "abstract". */
qx.Class.OVERLAY_ABSTRACT   = "api/overlay_abstract18.gif";
/** {string} The URL of the overlay "error". */
qx.Class.OVERLAY_ERROR      = "api/overlay_error18.gif";
/** {string} The URL of the overlay "inherited". */
qx.Class.OVERLAY_INHERITED  = "api/overlay_inherited18.gif";
/** {string} The URL of the overlay "overridden". */
qx.Class.OVERLAY_OVERRIDDEN = "api/overlay_overridden18.gif";
/** {string} The URL of the overlay "static". */
qx.Class.OVERLAY_STATIC     = "api/overlay_static18.gif";
/** {string} The URL of the overlay "warning". */
qx.Class.OVERLAY_WARN       = "api/overlay_warning18.gif";


/** {string} The icon URL of a package. */
qx.Class.ICON_PACKAGE      = "api/package18.gif";
/** {string} The icon URL of a package with warning. */
qx.Class.ICON_PACKAGE_WARN = "api/package_warning18.gif";


/** {string} The icon URL of a class. */
qx.Class.ICON_CLASS       = "api/class18.gif";
/** {string} The icon URL of a class with warning. */
qx.Class.ICON_CLASS_WARN  = "api/class_warning18.gif";
/** {string} The icon URL of a class with error. */
qx.Class.ICON_CLASS_ERROR = "api/class_warning18.gif";

/** {string} The icon URL of a static class. */
qx.Class.ICON_CLASS_STATIC       = "api/class_static18.gif";
/** {string} The icon URL of a static class with warning. */
qx.Class.ICON_CLASS_STATIC_WARN  = "api/class_static_warning18.gif";
/** {string} The icon URL of a static class with error. */
qx.Class.ICON_CLASS_STATIC_ERROR = "api/class_static_warning18.gif";

/** {string} The icon URL of an abstract class. */
qx.Class.ICON_CLASS_ABSTRACT       = "api/class_abstract18.gif";
/** {string} The icon URL of an abstract class with warning. */
qx.Class.ICON_CLASS_ABSTRACT_WARN  = "api/class_abstract_warning18.gif";
/** {string} The icon URL of an abstract class with error. */
qx.Class.ICON_CLASS_ABSTRACT_ERROR = "api/class_abstract_warning18.gif";


/** {string} The icon URL of a property. */
qx.Class.ICON_PROPERTY       = "api/property18.gif";
/** {string[]} The icon URL of a property with warning. */
qx.Class.ICON_PROPERTY_WARN  = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of a property with error. */
qx.Class.ICON_PROPERTY_ERROR = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an inherited property. */
qx.Class.ICON_PROPERTY_INHERITED       = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_INHERITED ];
/** {string[]} The icon URL of an inherited property with warning. */
qx.Class.ICON_PROPERTY_INHERITED_WARN  = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an inherited property with error. */
qx.Class.ICON_PROPERTY_INHERITED_ERROR = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an overridden property. */
qx.Class.ICON_PROPERTY_OVERRIDDEN       = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_OVERRIDDEN ];
/** {string[]} The icon URL of an overridden property with warning. */
qx.Class.ICON_PROPERTY_OVERRIDDEN_WARN  = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an overridden property with error. */
qx.Class.ICON_PROPERTY_OVERRIDDEN_ERROR = [ qx.Class.ICON_PROPERTY, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_ERROR ];


/** {string} The icon URL of an event. */
qx.Class.ICON_EVENT = "api/event18.gif";

/** {string[]} The icon URL of an inherited event. */
qx.Class.ICON_EVENT_INHERITED = [ qx.Class.ICON_EVENT, qx.Class.OVERLAY_INHERITED ];


/** {string} The icon URL of a public method. */
qx.Class.ICON_METHOD_PUB       = "api/method_public18.gif";
/** {string[]} The icon URL of a public method with warning. */
qx.Class.ICON_METHOD_PUB_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ERROR ];
/** {string[]} The icon URL of a public method with error. */
qx.Class.ICON_METHOD_PUB_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an inherited public method. */
qx.Class.ICON_METHOD_PUB_INHERITED       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_INHERITED ];
/** {string[]} The icon URL of an inherited public method with warning. */
qx.Class.ICON_METHOD_PUB_INHERITED_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an inherited public method with error. */
qx.Class.ICON_METHOD_PUB_INHERITED_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an overridden public method. */
qx.Class.ICON_METHOD_PUB_OVERRIDDEN       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_OVERRIDDEN ];
/** {string[]} The icon URL of an overridden public method with warning. */
qx.Class.ICON_METHOD_PUB_OVERRIDDEN_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an overridden public method with error. */
qx.Class.ICON_METHOD_PUB_OVERRIDDEN_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of a public static method. */
qx.Class.ICON_METHOD_PUB_STATIC       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_STATIC ];
/** {string[]} The icon URL of a public static method with error. */
qx.Class.ICON_METHOD_PUB_STATIC_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_STATIC, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of a public abstract method. */
qx.Class.ICON_METHOD_PUB_ABSTRACT       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT ];
/** {string[]} The icon URL of a public abstract method with warning. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of a public abstract method with error. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an overridden public abstract method. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_OVERRIDDEN       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_OVERRIDDEN ];
/** {string[]} The icon URL of an overridden public abstract method with warning. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_OVERRIDDEN_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an overridden public abstract method with error. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_OVERRIDDEN_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an inherited public abstract method. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_INHERITED       = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED ];
/** {string[]} The icon URL of an inherited public abstract method with warning. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_INHERITED_WARN  = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an inherited public abstract method with error. */
qx.Class.ICON_METHOD_PUB_ABSTRACT_INHERITED_ERROR = [ qx.Class.ICON_METHOD_PUB, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_ERROR ];


/** {string} The icon URL of a constructor. */
qx.Class.ICON_METHOD_PUB_CTOR       = "api/constructor18.gif";
/** {string[]} The icon URL of a constructor with error. */
qx.Class.ICON_METHOD_PUB_CTOR_ERROR = [ qx.Class.ICON_METHOD_PUB_CTOR, qx.Class.OVERLAY_ERROR ];


/** {string} The icon URL of a protected method. */
qx.Class.ICON_METHOD_PROT       = "api/method_protected18.gif";
/** {string[]} The icon URL of a protected method with warning. */
qx.Class.ICON_METHOD_PROT_WARN  = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ERROR ];
/** {string[]} The icon URL of a protected method with error. */
qx.Class.ICON_METHOD_PROT_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an inherited protected method. */
qx.Class.ICON_METHOD_PROT_INHERITED       = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_INHERITED ];
/** {string[]} The icon URL of an inherited protected method with warning. */
qx.Class.ICON_METHOD_PROT_INHERITED_WARN  = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an inherited protected method with error. */
qx.Class.ICON_METHOD_PROT_INHERITED_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an overridden protected method. */
qx.Class.ICON_METHOD_PROT_OVERRIDDEN       = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_OVERRIDDEN ];
/** {string[]} The icon URL of an overridden protected method with warning. */
qx.Class.ICON_METHOD_PROT_OVERRIDDEN_WARN  = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an overridden protected method with error. */
qx.Class.ICON_METHOD_PROT_OVERRIDDEN_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_OVERRIDDEN, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of a protected static method. */
qx.Class.ICON_METHOD_PROT_STATIC       = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_STATIC ];
/** {string[]} The icon URL of a protected static method with error. */
qx.Class.ICON_METHOD_PROT_STATIC_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_STATIC, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an abstract protected method. */
qx.Class.ICON_METHOD_PROT_ABSTRACT       = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT ];
/** {string[]} The icon URL of an abstract protected method with warning. */
qx.Class.ICON_METHOD_PROT_ABSTRACT_WARN  = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an abstract protected method with error. */
qx.Class.ICON_METHOD_PROT_ABSTRACT_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_ERROR ];

/** {string[]} The icon URL of an inherited abstract protected method. */
qx.Class.ICON_METHOD_PROT_ABSTRACT_INHERITED       = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED ];
/** {string[]} The icon URL of an inherited abstract protected method with warning. */
qx.Class.ICON_METHOD_PROT_ABSTRACT_INHERITED_WARN  = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_WARN ];
/** {string[]} The icon URL of an inherited abstract protected method with error. */
qx.Class.ICON_METHOD_PROT_ABSTRACT_INHERITED_ERROR = [ qx.Class.ICON_METHOD_PROT, qx.Class.OVERLAY_ABSTRACT, qx.Class.OVERLAY_INHERITED, qx.Class.OVERLAY_ERROR ];


/** {string} The icon URL of a constant. */
qx.Class.ICON_CONSTANT       = "api/constant18.gif";
/** {string[]} The icon URL of a constant with error. */
qx.Class.ICON_CONSTANT_ERROR = [ qx.Class.ICON_CONSTANT, qx.Class.OVERLAY_ERROR ];
