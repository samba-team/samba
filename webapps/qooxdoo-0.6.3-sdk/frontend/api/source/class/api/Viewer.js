/*
#module(api)
#resource(css:css)
#resource(images:image)
*/

/**
 * The API viewer. Shows the API documentation.
 */
qx.OO.defineClass("api.Viewer", qx.ui.layout.HorizontalBoxLayout,
function () {
  qx.ui.layout.HorizontalBoxLayout.call(this);

  this.setEdge(0);

  this._titlePrefix = this.getSetting("title") + " API Documentation";
  document.title = this._titlePrefix;

  this._tree = new qx.ui.tree.Tree("API Documentation");
  this._tree.set({
    backgroundColor: "white",
    overflow: "scroll",
    width: "22%",
    minWidth : 150,
    maxWidth : 300
  });
  this._tree.getManager().addEventListener("changeSelection", this._onTreeSelectionChange, this);
  this.add(this._tree);

  this._detailFrame = new qx.ui.layout.CanvasLayout;
  this._detailFrame.setWidth("1*");
  this._detailFrame.setBorder(qx.renderer.border.BorderPresets.horizontalDivider);
  this._detailFrame.setBackgroundColor("white");
  this._detailFrame.setHtmlProperty("id", "DetailFrame");
  this.add(this._detailFrame);

  this._detailLoader = new qx.ui.embed.HtmlEmbed('<h1><div class="please">please wait</div>Loading data...</h1>');
  this._detailLoader.setHtmlProperty("id", "DetailLoader");
  this._detailLoader.setMarginLeft(20);
  this._detailLoader.setMarginTop(20);
  this._detailFrame.add(this._detailLoader);

  this._classViewer = new api.ClassViewer;
  this._detailFrame.add(this._classViewer);

  this._infoViewer = new api.InfoViewer;
  this._detailFrame.add(this._infoViewer);

  this._currentTreeType = api.Viewer.PACKAGE_TREE;

  // Workaround: Since navigating in qx.ui.tree.Tree doesn't work, we've to
  //             maintain a hash that keeps the tree nodes for class names
  this._classTreeNodeHash = {};
  this._classTreeNodeHash[api.Viewer.PACKAGE_TREE] = {};
  this._classTreeNodeHash[api.Viewer.INHERITENCE_TREE] = {};

  api.Viewer.instance = this;

  qx.client.History.getInstance().init();
  qx.client.History.getInstance().addEventListener("request", this._onHistoryRequest, this);
});


/** The documentation tree to show. */
qx.OO.addProperty({ name:"docTree", type:"object" });


qx.Settings.setDefault("title", "qooxdoo");
qx.Settings.setDefault("initialTreeDepth", 1);


// property checker
qx.Proto._modifyDocTree = function(propValue, propOldValue, propData) {
  this._updateTree(propValue);
  return true;
}


/**
 * Loads the API doc tree from a URL. The URL must point to a JSON encoded
 * doc tree.
 *
 * @param url {string} the URL.
 */
qx.Proto.load = function(url)
{
  var req = new qx.io.remote.Request(url);

  req.setTimeout(180000);

  req.addEventListener("completed", function(evt)
  {
    var content = evt.getData().getContent();
    this.setDocTree(eval("(" + content + ")"));

    qx.ui.core.Widget.flushGlobalQueues();

    // Handle bookmarks
    if (window.location.hash) {
      var self = this;
      window.setTimeout(function() {
        self.selectItem(window.location.hash.substring(1));
      }, 0);
    }

    this._detailLoader.setHtml('<h1><div class="please">' + this.getSetting("title") +
        '</div>API Documentation</h1>');

  }, this);

  req.addEventListener("failed", function(evt)
  {
    this.error("Couldn't load file: " + url);
  }, this);

  req.send();
}


/**
 * Updates the tree on the left.
 *
 * @param docTree {Map} the documentation tree to use for updating.
 */
qx.Proto._updateTree = function(docTree) {
  var inheritenceNode = new qx.ui.tree.TreeFolder("Inheritence hierarchy");
  var packagesNode = new qx.ui.tree.TreeFolder("Packages");

  this._tree.removeAll();
  this._tree.add(inheritenceNode, packagesNode);

  // Fille the packages tree (and fill the _topLevelClassNodeArr)
  this._topLevelClassNodeArr = [];
  this._fillPackageNode(packagesNode, docTree, 0);

  // Sort the _topLevelClassNodeArr
  this._topLevelClassNodeArr.sort(function (node1, node2) {
    return (node1.attributes.fullName < node2.attributes.fullName) ? -1 : 1;
  });

  // Fill the inheritence tree
  for (var i = 0; i < this._topLevelClassNodeArr.length; i++) {
    this._createInheritanceNode(inheritenceNode, this._topLevelClassNodeArr[i], docTree);
  }

  packagesNode.open();

  if (this._wantedClassName) {
    this.showClassByName(this._wantedClassName);
    this._wantedClassName = null;
  }
}


/**
 * Fills a package tree node with tree nodes for the sub packages and classes.
 *
 * @param treeNode {qx.ui.tree.TreeFolder} the package tree node.
 * @param docNode {Map} the documentation node of the package.
 */
qx.Proto._fillPackageNode = function(treeNode, docNode, depth) {
  var ApiViewer = api.Viewer;
  var TreeUtil = api.TreeUtil;

  var packagesDocNode = TreeUtil.getChild(docNode, "packages");
  if (packagesDocNode && packagesDocNode.children) {
    for (var i = 0; i < packagesDocNode.children.length; i++) {
      var packageDocNode = packagesDocNode.children[i];
      var iconUrl = TreeUtil.getIconUrl(packageDocNode);
      var packageTreeNode = new qx.ui.tree.TreeFolder(packageDocNode.attributes.name, iconUrl);
      packageTreeNode.docNode = packageDocNode;
      treeNode.add(packageTreeNode);

      this._fillPackageNode(packageTreeNode, packageDocNode, depth+1);

      // Open the package node if it has child packages
      if (depth < this.getSetting("initialTreeDepth") && TreeUtil.getChild(packageDocNode, "packages")) {
        packageTreeNode.open();
      }

      // Register the tree node
      this._classTreeNodeHash[ApiViewer.PACKAGE_TREE][packageDocNode.attributes.fullName] = packageTreeNode;
    }
  }

  var classesDocNode = TreeUtil.getChild(docNode, "classes");
  if (classesDocNode && classesDocNode.children) {
    for (var i = 0; i < classesDocNode.children.length; i++) {
      var classDocNode = classesDocNode.children[i];
      var iconUrl = TreeUtil.getIconUrl(classDocNode);
      var classTreeNode = new qx.ui.tree.TreeFolder(classDocNode.attributes.name, iconUrl);
      classTreeNode.docNode = classDocNode;
      classTreeNode.treeType = ApiViewer.PACKAGE_TREE;
      treeNode.add(classTreeNode);

      // Register the tree node
      this._classTreeNodeHash[ApiViewer.PACKAGE_TREE][classDocNode.attributes.fullName] = classTreeNode;

      // Check whether this is a top-level-class
      if (classDocNode.attributes.superClass == null) {
        this._topLevelClassNodeArr.push(classDocNode);
      }
    }
  }
}


/**
 * Creates the tree node for a class containing class nodes for all its child
 * classes.
 *
 * @param classDocNode {Map} the documentation node of the class.
 * @param docTree {Map} the documentation tree.
 */
qx.Proto._createInheritanceNode = function(parentTreeNode, classDocNode, docTree) {
  var ApiViewer = api.Viewer;
  var TreeUtil = api.TreeUtil;

  // Create the tree node
  var iconUrl = TreeUtil.getIconUrl(classDocNode);
  var classTreeNode = new qx.ui.tree.TreeFolder(classDocNode.attributes.fullName, iconUrl);
  classTreeNode.docNode = classDocNode;
  classTreeNode.treeType = ApiViewer.INHERITENCE_TREE;
  parentTreeNode.add(classTreeNode);

  // Register the tree node
  this._classTreeNodeHash[ApiViewer.INHERITENCE_TREE][classDocNode.attributes.fullName] = classTreeNode;

  // Add all child classes
  var childClassNameCsv = classDocNode.attributes.childClasses;
  if (childClassNameCsv) {
    var childClassNameArr = childClassNameCsv.split(",");
    for (var i = 0; i < childClassNameArr.length; i++) {
      var childClassDocNode = TreeUtil.getClassDocNode(docTree, childClassNameArr[i]);
      this._createInheritanceNode(classTreeNode, childClassDocNode, docTree);
    }
  }
}


/**
 * Event handler. Called when the tree selection has changed.
 *
 * @param evt {Map} the event.
 */
qx.Proto._onTreeSelectionChange = function(evt)
{
  var treeNode = evt.getData()[0];

  if (treeNode && treeNode.docNode)
  {
    var newTitle = this._titlePrefix + " - class " + treeNode.docNode.attributes.fullName;

    qx.client.History.getInstance().addToHistory(treeNode.docNode.attributes.fullName, newTitle);

    this._currentTreeType = treeNode.treeType;

    this._selectTreeNode(treeNode);

    window.location.hash = "#" + treeNode.docNode.attributes.fullName;
  }
}


qx.Proto._onHistoryRequest = function(evt)
{
  this.showClassByName(evt.getData());
}

qx.Proto._selectTreeNode = function(vTreeNode)
{
  if (!(vTreeNode && vTreeNode.docNode)) {
    this.error("Invalid tree node: " + vTreeNode);
  }

  var vDoc = vTreeNode.docNode;

  this._detailLoader.setVisibility(false);

  if (vDoc.type == "class")
  {
    this._infoViewer.setVisibility(false);
    this._classViewer.showClass(vDoc);
    this._classViewer.setVisibility(true);
  }
  else
  {
    this._classViewer.setVisibility(false);
    this._infoViewer.showInfo(vDoc);
    this._infoViewer.setVisibility(true);
  }
}


/**
 * Selects an item (class, property, method or constant).
 *
 * @param fullItemName {string} the full name of the item to select.
 *        (e.g. "qx.mypackage.MyClass" or "qx.mypackage.MyClass#myProperty")
 */
qx.Proto.selectItem = function(fullItemName) {
  var className = fullItemName;
  var itemName = null;
  var hashPos = fullItemName.indexOf("#");
  if (hashPos != -1) {
    className = fullItemName.substring(0, hashPos);
    itemName = fullItemName.substring(hashPos + 1);

    var parenPos = itemName.indexOf("(");
    if (parenPos != -1) {
      itemName = qx.lang.String.trim(itemName.substring(0, parenPos));
    }
  }

  this.showClassByName(className);
  if (itemName) {
    this._classViewer.showItem(itemName);
  }
}


/**
 * Shows a certain class.
 *
 * @param className {string} the name of the class to show.
 */
qx.Proto.showClassByName = function(className) {
  var treeNode = this._classTreeNodeHash[this._currentTreeType][className];

  if (treeNode) {
    treeNode.setSelected(true);
  } else if (this.getDocTree() == null) {
    // The doc tree has not been loaded yet
    // -> Remeber the wanted class and show when loading is done
    this._wantedClassName = className;
  } else {
    this.error("Unknown class: " + className);
  }
}


qx.Class.PACKAGE_TREE = 1;
qx.Class.INHERITENCE_TREE = 2;



qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._tree)
  {
    this._tree.dispose();
    this._tree = null;
  }

  if (this._detailFrame)
  {
    this._detailFrame.dispose();
    this._detailFrame = null;
  }

  if (this._detailLoader)
  {
    this._detailLoader.dispose();
    this._detailLoader = null;
  }

  if (this._classViewer)
  {
    this._classViewer.dispose();
    this._classViewer = null;
  }

  if (this._infoViewer)
  {
    this._infoViewer.dispose();
    this._infoViewer = null;
  }

  this._classTreeNodeHash = null;

  return qx.ui.layout.HorizontalBoxLayout.prototype.dispose.call(this);
}
