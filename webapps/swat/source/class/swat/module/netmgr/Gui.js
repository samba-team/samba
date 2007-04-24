/*
 * Copyright (C)  Rafal Szczesniak 2007
 */


/**
 * Swat Net Manager class graphical user interface
 */
qx.OO.defineClass("swat.module.netmgr.Gui", qx.core.Target,
function()
{
  qx.core.Target.call(this);
});


//qx.OO.addProperty({ name : "_tree", type : "object" });
//qx.OO.addProperty({ name : "_panel", type : "object" });
//qx.OO.addProperty({ name : "_txtDomain", type : "object" });
//qx.OO.addProperty({ name : "_txtUsername", type : "object" });

/* NetContex resource number assigned on the server side.
   Necessary for every ejsnet call */
qx.OO.addProperty({ name : "netCtx", type : "number" });


qx.Proto.buildGui = function(module)
{
  var fsm = module.fsm;
  
  // Main layout composing the whole form
  var vlayout = new qx.ui.layout.VerticalBoxLayout();
  vlayout.set({
                top: 10,
                left: 10,
                right: 10,
                bottom: 20
              });

  // Horizontal layout holding TreeView and a "panel" for ListView
  var hlayout = new qx.ui.layout.HorizontalBoxLayout();
  hlayout.set({
                top: 0,
                left: 0,
                right: 0,
		height: "80%"
              });

  // Create a hosts tree
  this._tree = new qx.ui.treevirtual.TreeVirtual(["Hosts"]);
  var tree = this._tree;

  // Set the tree's properties
  tree.set({
             backgroundColor: 255,
	     border: qx.renderer.border.BorderPresets.getInstance().thinInset,
             overflow: "hidden",
             width: "20%",
             height: "100%",
             alwaysShowOpenCloseSymbol: true
           });

  tree.setCellFocusAttributes({ backgroundColor : "transparent" });

  // Create event listener
  tree.addEventListener("appear", fsm.eventListener, fsm);

  // Give a tree widget nicer name to handle
  fsm.addObject("tree", tree, "swat.main.fsmUtils.disable_during_rpc");

  // "Panel" for list view
  this._panel = new qx.ui.layout.VerticalBoxLayout();
  var panel = this._panel;

  // TODO: Find out what's causing this bug - specifying 'width' works fine,
  // but setting 'right' instead does not which makes impossible to position
  // the panel against right boundary of a box
  panel.set({
              top: 0,
              left: 10,
              width:"80%",
              height: "100%"
            });

  // Add the tree view and panel for list view to the layout
  hlayout.add(tree);
  hlayout.add(panel);

  // Status layout containing informative labels and status information
  var statusLayout = new qx.ui.layout.HorizontalBoxLayout();
  statusLayout.set({
                     top: 10,
                     left: 0,
                     width: "100%",
                     height: "20%"
                   });

  // First "column" of status fields
  var colALayout = new qx.ui.layout.VerticalBoxLayout();
  colALayout.set({
                  top: 0,
                  left: 0,
                  width: "25%",
                  height: "100%"
                });

  // Domain name (credentials) - label and text box
  var statusDomain = new qx.ui.layout.HorizontalBoxLayout();
  statusDomain.set({ top: 0, left: 0, width: "100%", height: "auto",
		       verticalChildrenAlign: "middle" });
  
  var lblDomain = new qx.ui.basic.Atom();
  lblDomain.setLabel("Domain:");
  lblDomain.set({ width: 70, right: 5, horizontalChildrenAlign: "right" });

  var txtDomain = new qx.ui.form.TextField();
  txtDomain.set({ width: 80, readOnly: true });
  this._txtDomain = txtDomain;

  statusDomain.add(lblDomain);
  statusDomain.add(txtDomain);
  
  // Username (credentials) - label and text box
  var statusUsername = new qx.ui.layout.HorizontalBoxLayout();
  statusUsername.set({ top: 0, left: 0, width: "100%", height: "auto",
                       verticalChildrenAlign: "middle" });

  var lblUsername = new qx.ui.basic.Atom();
  lblUsername.setLabel("Username:");
  lblUsername.set({ width: 70, right: 5, horizontalChildrenAlign: "right" });
  
  var txtUsername = new qx.ui.form.TextField();
  txtUsername.set({ width: 80, readOnly: true });
  this._txtUsername = txtUsername;
  
  statusUsername.add(lblUsername);
  statusUsername.add(txtUsername);
  
  colALayout.add(statusDomain);
  colALayout.add(statusUsername);

  statusLayout.add(colALayout);
  
  vlayout.add(hlayout);
  vlayout.add(statusLayout);

  vlayout.addEventListener("appear", fsm.eventListener, fsm);
  fsm.addObject("vlayout", vlayout);

  // place everything on canvas
  module.canvas.add(vlayout);

  // Add event handler to netCtx property change
  this.addEventListener("changeNetCtx", fsm.eventListener, fsm);
  fsm.addObject("swat.module.netmgr.Gui", this);
};


qx.Proto.displayData = function(module, rpcRequest)
{
  var gui = module.gui;
  var fsm = module.fsm;
  var result = rpcRequest.getUserData("result");
  var requestType = rpcRequest.getUserData("requestType");

  // Something went wrong
  if (result.type == "failed")
  {
    alert("Async(" + result.id + ") exception: " + result.data);
    return;
  }

  switch (requestType)
  {
    case "hostname":
    // Add local host node
    this._addHostNode(module, rpcRequest, true);
    break;

    case "NetContext":
    this._initNetContext(module, rpcRequest);
    break;

    case "NetContextCreds":
    this._updateNetContextCreds(module, rpcRequest);
    break;

    case "UserMgr":
    this._initUserManager(module, rpcRequest);
    break;
  }

  qx.ui.core.Widget.flushGlobalQueues();
};


qx.Proto.getParentNode = function(module, node)
{
  var tree = this._tree;
  var nodes = tree.getTableModel().getData();
  if (nodes == undefined)
  {
    return undefined;
  }

  if (node.parentNodeId == 0)
  {
    // there is no parent node
    return node;
  }
  
  var parentNode = nodes[node.parentNodeId];
  return parentNode;
};


qx.Proto.openUserManager = function(module, domainName)
{
  // Remove existing panel if there is any - there can be only one at the time
  if (this._panel.hasChildren())
  {
    this._panel.removeAll();
  }

  // Create user view, pass the context and the view to the panel
  var view = new swat.module.netmgr.UsersView(module.fsm, domainName);
  this._panel.add(view);
};


qx.Proto._addHostNode = function(module, rpcRequest, local)
{
  var fsm = module.fsm;
  var hostname = rpcRequest.getUserData("result").data;

  // Get the tree widget
  var tree = this._tree;
  var dataModel = tree.getDataModel();
  
  // Add new host and its service leaves
  var hostNodeId = dataModel.addBranch(null, hostname, false);
  
  var domainNodeId = dataModel.addLeaf(hostNodeId, "Domain", false);
  var usersNodeId = dataModel.addLeaf(hostNodeId, "Users", false);
  var groupsNodeId = dataModel.addLeaf(hostNodeId, "Groups", false);
  var srvcsNodeId = dataModel.addLeaf(hostNodeId, "Services", false);
  
  dataModel.setData();
  tree.addEventListener("changeSelection", fsm.eventListener, fsm);

  var hostNode = dataModel.getData()[hostNodeId];

  // Set host-specific properties
  hostNode.netCtx = undefined;
  hostNode.local = local;
};


qx.Proto._initNetContext = function(module, rpcRequest)
{
  // Gather obtained NetContext handle
  var result = rpcRequest.getUserData("result").data;
  this.setNetCtx(result);
};


qx.Proto._updateNetContextCreds = function(module, rpcRequest)
{
  // Get requested credentials from the current NetContext
  var result = rpcRequest.getUserData("result").data;
  this._txtUsername.setValue(result.username);
  this._txtDomain.setValue(result.domain);
};


qx.Proto._initUserManager = function(module, rpcRequest)
{
  // Get obtained usrCtx handle
  var usrCtx = rpcRequest.getUserData("result").data;
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
