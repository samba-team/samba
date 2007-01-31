/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat LDB Browser class graphical user interface
 */
qx.OO.defineClass("swat.module.ldbbrowse.Gui", qx.core.Object,
function()
{
  qx.core.Object.call(this);
});

//qx.OO.addProperty({ name : "_table", type : "object" });
//qx.OO.addProperty({ name : "_ldbmod", type : "object" });

/**
 * Build the raw graphical user interface.
 */
qx.Proto.buildGui = function(module)
{
  var o;
  var fsm = module.fsm;

  // We need a horizontal box layout for the database name
  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.set({
                  top: 20,
                  left: 20,
                  right: 20,
                  height: 30
              });

  // Create a label for the database name
  o = new qx.ui.basic.Atom("Database:");
  o.setWidth(100);
  o.setHorizontalChildrenAlign("right");

  // Add the label to the horizontal layout
  hlayout.add(o);

  // Create a combo box for for the database name
  o = new qx.ui.form.ComboBox();
  o.getField().setWidth("100%");
  o.setEditable(false);

  // Add our global database name (the only option, for now)
  var item = new qx.ui.form.ListItem(module.dbFile);
  o.add(item);
  
  // We want to be notified if the selection changes
  o.addEventListener("changeSelection", fsm.eventListener, fsm);

  // Save the database name object so we can react to changes
  fsm.addObject("dbName", o);
    
  // Add the combo box to the horizontal layout
  hlayout.add(o);

  // Add the database name selection to the canvas
  module.canvas.add(hlayout);

  // Create and position the tabview
  var tabView_ = new qx.ui.pageview.tabview.TabView;
  tabView_.set({
                   top: 60,
                   left: 20,
                   right: 20,
                   bottom: 20
               });

  // Create each of the tabs
  var tabView_Browse =
  new qx.ui.pageview.tabview.Button("Browse");
  var tabView_Search =
  new qx.ui.pageview.tabview.Button("Search");

  // Specify the initially-selected tab
  tabView_Browse.setChecked(true);

  // Add each of the tabs to the tabview
  tabView_.getBar().add(tabView_Browse, tabView_Search);

  // Create the pages to display when each tab is selected
  var tabViewPage_Browse =
  new qx.ui.pageview.tabview.Page(tabView_Browse);
  var tabViewPage_Search =
  new qx.ui.pageview.tabview.Page(tabView_Search);

  // Build the browse page
  this._buildPageBrowse(module, tabViewPage_Browse);

  // Build the search page
  this._buildPageSearch(module, tabViewPage_Search);

  // Add the pages to the tabview
  tabView_.getPane().add(tabViewPage_Browse, tabViewPage_Search);

  // Add the tabview to our canvas
  module.canvas.add(tabView_);
};


/**
 * Populate the graphical user interface with the specified data
 *
 * @param module {swat.main.Module}
 *   The module descriptor for the module.
 *
 * @result {Object}
 *   The result returned by SAMBA to our request.  We display the data
 *   provided by this result.
 */
qx.Proto.displayData = function(module, rpcRequest)
{
  var gui = module.gui;
  var fsm = module.fsm;
  var result = rpcRequest.getUserData("result")
  var requestType = rpcRequest.getUserData("requestType");

  // Did the request fail?
  if (result.type == "failed")
  {
    // Yup.  We're not going to do anything particularly elegant...
    alert("Async(" + result.id + ") exception: " + result.data);
    return;
  }

  // Dispatch to the appropriate handler, depending on the request type
  switch(requestType)
  {
  case "search":
    this._displaySearchResults(module, rpcRequest);
    break;
    
  case "tree_open":
    this._displayTreeOpenResults(module, rpcRequest);
    break;

  case "tree_selection_changed":

    // Always update the table, even if it is not visible
    this._displayTreeSelectionChangedResults(module, rpcRequest);

    // Update the base field in ldbmod
    this._displayLdbmodBaseChanged(module, rpcRequest);

    break;

  case "database_name_changed":
    this._clearAllFields(module, rpcRequest);
    break;

  default:
    throw new Error("Unexpected request type: " + requestType);
  }

  // Force flushing of pending DOM updates.  This is actually a
  // work-around for a bug.  Without this, occasionally, updates to the
  // gui aren't displayed until some 'action' takes place, e.g. key
  // press or mouse movement.
  qx.ui.core.Widget.flushGlobalQueues();
};


qx.Proto._setAppearances = function()
{
    // Modify the default appearance of a ComboBox for use in Search tab:
    //   use more of the available width.
    //
    // If we had multiple uses, we'd create a new appearance which didn't
    // contain a width.  That way, we'd be able to assign a specific width to
    // each ComboBox instance.  Since we don't have multiple of them, we can
    // just modify this default appearance.
    //
    // See http://qooxdoo.org/documentation/user_manual/appearance for an
    // explanation of what's going on here.  The missing significant point in
    // the discussion is that in the current qooxdoo appearance
    // implementation, it's not possible to override a specific widget's
    // appearance with explicit settings just for that widget (stupid!).  I
    // expect that to change in a future version.
    var appMgr = qx.manager.object.AppearanceManager.getInstance();
    var theme = appMgr.getAppearanceTheme();
    var appearance = theme._appearances["combo-box"];
    if (! appearance)
    {
        return;
    }
    var oldInitial = appearance.initial;
    appearance.initial = function(vTheme)
    {
        var res = oldInitial ? oldInitial.apply(this, arguments) : {};
        res.width = "80%";
        return res;
    }
};


qx.Proto._buildPageSearch = function(module, page)
{
  var fsm = module.fsm;

  // We need a vertical box layout for the various input fields
  var vlayout = new qx.ui.layout.VerticalBoxLayout();
  vlayout.set({
               overflow: "hidden",
               height: 120,
               top: 10,
               left: 0,
               right: 0,
               bottom: 10
           });

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Search Expression");
  label.setHorizontalChildrenAlign("left");

  // Add the label to the horizontal layout
  vlayout.add(label);

  // Create a combo box for entry of the search expression
  var filter = new qx.ui.form.TextField();
  filter.set({ width:300 });
  fsm.addObject("searchExpr", filter);
    
  // Add the combo box to the horizontal layout
  vlayout.add(filter);

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Base");
  label.setHorizontalChildrenAlign("left");

  // Add the label to the horizontal layout
  vlayout.add(label);

  // Create a combo box for entry of the search expression
  var base = new qx.ui.form.TextField();
  base.set({ width:300 });
  fsm.addObject("baseDN", base);
    
  // Add the combo box to the horizontal layout
  vlayout.add(base);

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Scope");
  label.setWidth(100);
  label.setHorizontalChildrenAlign("left");

  // Add the label to the scope vertical layout
  vlayout.add(label);

  // Use a horizontal box layout to keep the search button aligned
  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.setWidth(300);
  hlayout.setHeight(30);

  var cbScope = new qx.ui.form.ComboBoxEx();
  cbScope.setSelection([ ["subtree", "Subtree"], ["one", "One Level"], ["base", "Base"]]);
  cbScope.setSelectedIndex(0);

  fsm.addObject("scope", cbScope);

  hlayout.add(cbScope);

  // Add a sapcer
  hlayout.add(new qx.ui.basic.HorizontalSpacer());

  // Create the 'Search' button
  var search = new qx.ui.form.Button('Search');
  search.setWidth(100);
  search.addEventListener("execute", fsm.eventListener, fsm);

  // We'll be receiving events on the search object, so save its friendly name
  fsm.addObject("search", search, "swat.main.fsmUtils.disable_during_rpc");

  // Add the search button to the vertical layout
  hlayout.add(search);

  vlayout.add(hlayout);

  // Add the vlayout to the page
  page.add(vlayout);

  var ldifview = new swat.module.ldbbrowse.LdifViewer();
  ldifview.set({
               top: 130,
               left: 10,
               right: 10,
               bottom: 10
           });

  fsm.addObject("LdifView", ldifview);

  // Add the output area to the page
  page.add(ldifview);
};

qx.Proto._buildPageBrowse = function(module, page)
{
  var fsm = module.fsm;

  // Create a horizontal splitpane for tree (left) and table (right)
  var splitpane = new qx.ui.splitpane.HorizontalSplitPane("1*", "2*");
  splitpane.setEdge(0);

  // We need a vertical box layout for the tree and the buttons
  var vlayout = new qx.ui.layout.VerticalBoxLayout();
  vlayout.set({
               height: "100%",
               top: 5,
               left: 5,
               right: 5,
               bottom: 5,
               spacing: 10
           });

  // Create a tree row structure for the tree root
  var trsInstance = qx.ui.treefullcontrol.TreeRowStructure.getInstance();
  var trs = trsInstance.standard(module.dbFile);

  // Create the tree and set its characteristics
  var tree = new qx.ui.treefullcontrol.Tree(trs);
  tree.set({
               backgroundColor: 255,
               border: qx.renderer.border.BorderPresets.getInstance().inset,
               overflow: "auto",
               height: "1*",
               open: false,
               alwaysShowPlusMinusSymbol: true
           });

  // All subtrees will use this root node's event listeners.  Create an event
  // listener for an open while empty.
  tree.addEventListener("treeOpenWhileEmpty", fsm.eventListener, fsm);

  // All subtrees will use this root node's event listeners.  Create an event
  // listener for selection changed, to populate attribute/value table
  tree.getManager().addEventListener("changeSelection",
                                     fsm.eventListener,
                                     fsm);

  // We'll be receiving events on the tree object, so save its friendly name
  fsm.addObject("tree", tree);
  fsm.addObject("tree:manager", tree.getManager());

  // Add the tree to the vlayout.
  vlayout.add(tree);

  // Add an horizonatl layout for the "New" and "Modify" buttons
  // We need a vertical box layout for the tree and the buttons
  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.set({
               height: "auto",
               spacing: 10
           });

  // Add the "New" button
  this._newb = new qx.ui.form.Button("New");
  this._newb.addEventListener("execute", this._switchToNewrecord, this);

  // Add the button to the hlayout
  hlayout.add(this._newb);

  // Add the "New" button
  this._modb = new qx.ui.form.Button("Modify");
  this._modb.addEventListener("execute", this._switchToModrecord, this);

  // Add the button to the hlayout
  hlayout.add(this._modb);
  
  // Add the hlayout to the vlayout.
  vlayout.add(hlayout);

  //Add the left vlayout to the splitpane
  splitpane.addLeft(vlayout);

  // Create a simple table model
  var tableModel = new qx.ui.table.SimpleTableModel();
  tableModel.setColumns([ "Attribute", "Value" ]);

  tableModel.setColumnEditable(0, false);
  tableModel.setColumnEditable(1, false);
  fsm.addObject("tableModel:browse", tableModel);

  // Create a table
  this._table = new qx.ui.table.Table(tableModel);
  this._table.set({
                top: 10,
                left: 0,
                right: 0,
                bottom: 10,
                statusBarVisible: false,
                columnVisibilityButtonVisible: false
            });
  this._table.setColumnWidth(0, 180);
  this._table.setColumnWidth(1, 320);
  this._table.setMetaColumnCounts([1, -1]);
  fsm.addObject("table:browse", this._table);

  //table.setDisplay(false);

  // Add the table to the bottom portion of the splitpane
  splitpane.addRight(this._table);

  // Build the create/modify widget
  this._ldbmod = new swat.module.ldbbrowse.LdbModify(fsm);
  this._ldbmod.set({
                top: 10,
                left: 0,
                right: 0,
                bottom: 10
            });
  // Not displayed by default
  this._ldbmod.setDisplay(false);

  fsm.addObject("ldbmod:browse", this._ldbmod);

  splitpane.addRight(this._ldbmod);

  // Add the first splitpane to the page
  page.add(splitpane);
};

qx.Proto._switchToNormal = function()
{
  this._table.setDisplay(true);
  this._ldbmod.setDisplay(false);
  this._newb.setEnabled(true);
  this._modb.setEnabled(true);
}

qx.Proto._switchToNewrecord = function()
{
  this._table.setDisplay(false);
  this._ldbmod.setDisplay(true);
  this._newb.setEnabled(false);
  this._modb.setEnabled(false);
  this._ldbmod.initNew(this._switchToNormal, this);
}

qx.Proto._switchToModrecord = function()
{
  this._table.setDisplay(false);
  this._ldbmod.setDisplay(true);
  this._newb.setEnabled(false);
  this._modb.setEnabled(false);
  this._ldbmod.initMod(this._table.getTableModel(), this._switchToNormal, this);
}

qx.Proto._displaySearchResults = function(module, rpcRequest)
{
  var fsm = module.fsm;

  // Obtain the ldif object
  var ldifview = fsm.getObject("LdifView");

  ldifview.reset();

  // Obtain the result object
  result = rpcRequest.getUserData("result").data;

  if (result && result["length"])
  {
    len = result["length"];
    for (var i = 0; i < result["length"]; i++)
    {
      var obj = result[i];
      if (typeof(obj) != "object")
      {
        alert("Found unexpected result, type " +
              typeof(obj) +
              ", " +
              obj +
              "\n");
        continue;
      }
      ldifview.appendObject(obj);
    }
  }
  else
  {
    alert("No results.");
  }
};


qx.Proto._displayTreeOpenResults = function(module, rpcRequest)
{
  var t;
  var trs;
  var child;

  // Obtain the result object
  var result = rpcRequest.getUserData("result").data;

  // We also need some of the original parameters passed to the request
  var parent = rpcRequest.getUserData("parent");
  var attributes = rpcRequest.getUserData("attributes");

  // Any children?
  if (! result || result["length"] == 0)
  {
    // Nope.  Allow parent's expand/contract button to be removed
    parent.setAlwaysShowPlusMinusSymbol(false);
    return;
  }

  // base object, add naming contexts to the root
  if ((result.length == 1) &&
      ((result[0]["dn"] == "") ||
       (result[0]["dn"].toLowerCase() == "cn=rootdse"))) {

    defnc = result[0]["defaultNamingContext"];

    // Build a tree row for the defaultNamingContext
    if (defnc) {
      trs = qx.ui.treefullcontrol.TreeRowStructure.getInstance().standard(defnc);
      // This row is a "folder" (it can have children)
      t = new qx.ui.treefullcontrol.TreeFolder(trs);
      t.setAlwaysShowPlusMinusSymbol(true);

      // Add this row to its parent
      parent.add(t);
    }

    var ncs = result[0]["namingContexts"];

    // If it's multi-valued (type is an array) we have other naming contexts to show
    if (typeof(ncs) == "object") {
      
      for (var i = 0; i < ncs.length; i++) {
        if (ncs[i] != defnc) { //skip default naming context
          trs = qx.ui.treefullcontrol.TreeRowStructure.getInstance().standard(ncs[i]);
          // This row is a "folder" (it can have children)
          t = new qx.ui.treefullcontrol.TreeFolder(trs);
          t.setAlwaysShowPlusMinusSymbol(true);
  
          // Add this row to its parent
          parent.add(t);
        }
      }
    }
  }
  else {

    for (var i = 0; i < result.length; i++)
    {
      var name;
  
      child = result[i];
  
      name = child["dn"].split(",")[0];
  
      // Build a standard tree row
      trs = qx.ui.treefullcontrol.TreeRowStructure.getInstance().standard(name);
  
      // This row is a "folder" (it can have children)
      t = new qx.ui.treefullcontrol.TreeFolder(trs);
      t.setAlwaysShowPlusMinusSymbol(true);
  
      // Add this row to its parent
      parent.add(t);
    }

  }
};

qx.Proto._displayLdbmodBaseChanged = function(module, rpcRequest)
{
  var fsm = module.fsm;

  // Obtain the result object
  var result = rpcRequest.getUserData("result").data;

  // If we received an empty list, ...
  if (result == null)
  {
    // ... then ??
    return;
  }

  this._ldbmod.setBase(result[0]["dn"]);
};

qx.Proto._displayTreeSelectionChangedResults = function(module, rpcRequest)
{
  var fsm = module.fsm;

  // Obtain the result object
  var result = rpcRequest.getUserData("result").data;

  // If we received an empty list, ...
  if (result == null)
  {
    // ... then just clear the attribute/value table.
    tableModel.setData([ ]);
    return;
  }

  // Start with an empty table dataset
  var rowData = [ ];

  // The result contains a single object: attributes
  var attributes = result[0];

  // Track the maximum length of the attribute values
  var maxLen = 0;

  // For each attribute we received...
  for (var attr in attributes)
  {
    // If it's multi-valued (type is an array)...
    if (typeof(attributes[attr]) == "object")
    {
      // ... then add each value with same name
      var a = attributes[attr];
      for (var i = 0; i < a.length; i++)
      {
        if (a[i].length > maxLen)
        {
          maxLen = a[i].length;
        }
        rowData.push([ attr, a[i] ]);
      }
    }
    else    // single-valued
    {
      // ... add its name and value to the table dataset
      if (attributes[attr].length > maxLen)
      {
        maxLen = attributes[attr].length;
      }
      rowData.push([ attr, attributes[attr] ]);
    }
  }

  // Obtain the table and tableModel objects
  var table = fsm.getObject("table:browse");
  var tableModel = fsm.getObject("tableModel:browse");

  // Adjust the width of the value column based on maxLen
  table.setColumnWidth(1, maxLen * 7);

  // Add the dataset to the table
  tableModel.setData(rowData);
};


qx.Proto._clearAllFields = function(module, rpcRequest)
{
  // Obtain the result object
  var result = rpcRequest.getUserData("result").data;

  // Retrieve the database handle
  module.dbHandle = result;

  // In the future, when we support more than one database, we'll want to
  // clear all fields here.  For now, there's no need.
};



/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
