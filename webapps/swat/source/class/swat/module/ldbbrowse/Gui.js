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
  var tabView_Search =
  new qx.ui.pageview.tabview.Button("Search");
  var tabView_Browse =
  new qx.ui.pageview.tabview.Button("Browse");

  // Specify the initially-selected tab
  tabView_Search.setChecked(true);

  // Add each of the tabs to the tabview
  tabView_.getBar().add(tabView_Search, tabView_Browse);

  // Create the pages to display when each tab is selected
  var tabViewPage_Search =
  new qx.ui.pageview.tabview.Page(tabView_Search);
  var tabViewPage_Browse =
  new qx.ui.pageview.tabview.Page(tabView_Browse);

  // Build the search page
  this._buildPageSearch(module, tabViewPage_Search);

  // Build the browse page
  this._buildPageBrowse(module, tabViewPage_Browse);

  // Add the pages to the tabview
  tabView_.getPane().add(tabViewPage_Search, tabViewPage_Browse);

  // Add the tabview to our canvas
  module.canvas.add(tabView_);
};


/**
 * Populate the graphical user interface with the specified data
 *
 * @param module {swat.module.Module}
 *   The module descriptor for the module.
 *
 * @result {Object}
 *   The result returned by SAMBA to our request.  We display the data
 *   provided by this result.
 */
qx.Proto.displayData = function(module, request)
{
  var gui = module.gui;
  var fsm = module.fsm;
  var result = request.getUserData("result")
  var requestType = request.getUserData("requestType");

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
  case "find":
    this._displayFindResults(module, request);
    break;
    
  case "tree_open":
    this._displayTreeOpenResults(module, request);
    break;

  case "tree_selection_changed":
    this._displayTreeSelectionChangedResults(module, request);
    break;

  case "database_name_changed":
    this._clearAllFields(module, request);
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
  vlayout.setWidth("100%");

  // We need a horizontal box layout for the search combo box and its label
  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.setWidth("100%");
  hlayout.setHeight(25);

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Search Expression:");
  label.setWidth(100);
  label.setHorizontalChildrenAlign("right");

  // Add the label to the horizontal layout
  hlayout.add(label);

  // Create a combo box for entry of the search expression
  var search = new qx.ui.form.ComboBox();
  search.getField().setWidth("100%");
  search.setEditable(true);
  fsm.addObject("searchExpr", search);
    
  // Add the combo box to the horizontal layout
  hlayout.add(search);

  // Add the horizontal layout to the vertical layout
  vlayout.add(hlayout);

  // We need a horizontal box layout for the base combo box and its label
  hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.setWidth("100%");
  hlayout.setHeight(25);

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Base:");
  label.setWidth(100);
  label.setHorizontalChildrenAlign("right");

  // Add the label to the horizontal layout
  hlayout.add(label);

  // Create a combo box for entry of the search expression
  var base = new qx.ui.form.ComboBox();
  base.getField().setWidth("100%");
  base.setEditable(true);
  fsm.addObject("baseDN", base);
    
  // Add the combo box to the horizontal layout
  hlayout.add(base);

  // Add the horizontal layout to the vertical layout
  vlayout.add(hlayout);

  // We need a horizontal box layout for scope radio buttons
  hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.setWidth("100%");
  hlayout.setHeight(25);

  // Create a label for the list of required attributes
  var label = new qx.ui.basic.Atom("Scope:");
  label.setWidth(100);
  label.setHorizontalChildrenAlign("right");

  // Add the label to the horizontal layout
  hlayout.add(label);

  // Create a radio button for each scope
  var rbDefault = new qx.ui.form.RadioButton("Default",   "default");
  var rbBase    = new qx.ui.form.RadioButton("Base",      "base");
  var rbOne     = new qx.ui.form.RadioButton("One Level", "one");
  var rbSubtree = new qx.ui.form.RadioButton("Subtree",   "subtree");

  // Use a default of "Default"
  rbBase.setChecked(true);

  // Add the radio buttons to the horizontal layout
  hlayout.add(rbDefault, rbBase, rbOne, rbSubtree);

  // Group the radio buttons so only one in the group may be selected
  var scope = new qx.manager.selection.RadioManager("scope",
                                                    [
                                                        rbDefault,
                                                        rbBase,
                                                        rbOne,
                                                        rbSubtree
                                                    ]);
  fsm.addObject("scope", scope);
    
  // Right-justify the 'Find' button
  var spacer = new qx.ui.basic.HorizontalSpacer;
  hlayout.add(spacer);

  // Create the 'Find' button
  var find = new qx.ui.form.Button('Find');
  find.setWidth(100);
  find.addEventListener("execute", fsm.eventListener, fsm);

  // We'll be receiving events on the find object, so save its friendly name
  fsm.addObject("find", find, "swat.module.fsmUtils.disable_during_rpc");

  hlayout.add(find);

  // Add the Find button line to the vertical layout
  vlayout.add(hlayout);

  // Add the horizontal box layout to the page
  page.add(vlayout);

  // Create a simple table model
  var tableModel = new qx.ui.table.SimpleTableModel();
  tableModel.setColumns([ "Distinguished Name", "Attribute", "Value" ]);

  tableModel.setColumnEditable(0, false);
  tableModel.setColumnEditable(1, false);
  tableModel.setColumnEditable(2, false);
  fsm.addObject("tableModel:search", tableModel);

  // Create a table
  var table = new qx.ui.table.Table(tableModel);
  table.set({
                top: 80,
                left: 0,
                right: 0,
                bottom: 10,
                statusBarVisible: false,
                columnVisibilityButtonVisible: false
            });
  table.setColumnWidth(0, 300);
  table.setColumnWidth(1, 180);
  table.setColumnWidth(2, 240);
  table.setMetaColumnCounts([ 1, -1 ]);// h-scroll attribute and value together
  fsm.addObject("table:search", table);

  page.add(table);
};

qx.Proto._buildPageBrowse = function(module, page)
{
  var fsm = module.fsm;

  // Create a vertical splitpane for tree (top) and table (bottom)
  var splitpane = new qx.ui.splitpane.VerticalSplitPane("1*", "2*");
  splitpane.setEdge(0);

  // Create a tree row structure for the tree root
  var trsInstance = qx.ui.treefullcontrol.TreeRowStructure.getInstance();
  var trs = trsInstance.standard(module.dbFile);

  // Create the tree and set its characteristics
  var tree = new qx.ui.treefullcontrol.Tree(trs);
  tree.set({
               backgroundColor: 255,
               border: qx.renderer.border.BorderPresets.getInstance().inset,
               overflow: "auto",
               height: null,
               top: 10,
               left: 0,
               right: 0,
               bottom: 10,
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

  // Add the tree to the page.
  splitpane.addTop(tree);

  // Create a simple table model
  var tableModel = new qx.ui.table.SimpleTableModel();
  tableModel.setColumns([ "Attribute", "Value" ]);

  tableModel.setColumnEditable(0, false);
  tableModel.setColumnEditable(1, false);
  fsm.addObject("tableModel:browse", tableModel);

  // Create a table
  var table = new qx.ui.table.Table(tableModel);
  table.set({
                top: 10,
                left: 0,
                right: 0,
                bottom: 10,
                statusBarVisible: false,
                columnVisibilityButtonVisible: false
            });
  table.setColumnWidth(0, 200);
  table.setColumnWidth(1, 440);
  table.setMetaColumnCounts([1, -1]);
  fsm.addObject("table:browse", table);

  // Add the table to the bottom portion of the splitpane
  splitpane.addBottom(table);

  // Add the first splitpane to the page
  page.add(splitpane);
};


qx.Proto._displayFindResults = function(module, request)
{
  var rowData = [];
  var fsm = module.fsm;

  // Track the maximum length of the attribute values
  var maxLen = 0;

  // Obtain the result object
  result = request.getUserData("result").data;

  if (result && result["length"])
  {
    len = result["length"];
    for (var i = 0; i < result["length"]; i++)
    {
      var o = result[i];
      if (typeof(o) != "object")
      {
        alert("Found unexpected result, type " +
              typeof(o) +
              ", " +
              o +
              "\n");
        continue;
      }
      for (var field in o)
      {
        // skip dn and distinguishedName fields;
        // they're shown in each row anyway.
        if (field == "dn" || field == "distinguishedName")
        {
          continue;
        }

        // If it's multi-valued (type is an array)...
        if (typeof(o[field]) == "object")
        {
          // ... then add each value with same name
          var a = o[field];
          for (var i = 0; i < a.length; i++)
          {
            if (a[i].length > maxLen)
            {
              maxLen = a[i].length;
            }
            rowData.push( [
                            o["dn"],
                            field,
                            a[i]
                            ] );
          }
        }
        else    // single-valued
        {
          // ... add its name and value to the table
          // dataset
          if (o[field].length > maxLen)
          {
            maxLen = o[field].length;
          }
          rowData.push( [
                          o["dn"],
                          field,
                          o[field]
                          ] );
        }
      }

      // Obtain the table and tableModel objects
      var table = fsm.getObject("table:search");
      var tableModel = fsm.getObject("tableModel:search");

      // Adjust the width of the value column based on
      // maxLen
      table.setColumnWidth(2, maxLen * 7);

      // Tell the table to use the new data
      tableModel.setData(rowData);
    }
  }
  else
  {
    alert("No rows returned.");
  }
};


qx.Proto._displayTreeOpenResults = function(module, request)
{
  var t;
  var trs;
  var child;

  // Obtain the result object
  var result = request.getUserData("result").data;

  // We also need some of the original parameters passed to the request
  var parent = request.getUserData("parent");
  var attributes = request.getUserData("attributes");

  // Any children?
  if (! result || result["length"] == 0)
  {
    // Nope.  Allow parent's expand/contract button to be removed
    parent.setAlwaysShowPlusMinusSymbol(false);
    return;
  }

  for (var i = 0; i < result.length; i++)
  {
    var name;

    child = result[i];

    // Determine name for new tree row.  If first level, use entire
    // DN.  Otherwise, strip off first additional component.
    if (attributes == "defaultNamingContext")
    {
      name = child["defaultNamingContext"];
    }
    else
    {
      name = child["dn"].split(",")[0];
    }

    // Build a standard tree row
    trs = qx.ui.treefullcontrol.TreeRowStructure.getInstance().standard(name);

    // This row is a "folder" (it can have children)
    t = new qx.ui.treefullcontrol.TreeFolder(trs);
    t.setAlwaysShowPlusMinusSymbol(true);

    // Add this row to its parent
    parent.add(t);
  }
};


qx.Proto._displayTreeSelectionChangedResults = function(module, request)
{
  var fsm = module.fsm;

  // Obtain the result object
  var result = request.getUserData("result").data;

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


qx.Proto._clearAllFields = function(module, request)
{
  // Obtain the result object
  var result = request.getUserData("result").data;

  // Retrieve the database handle
  module.dbHandle = result;

  // In the future, when we support more than one database, we'll want to
  // clear all fields here.  For now, there's no need.
};



/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
