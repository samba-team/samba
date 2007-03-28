/*
 * Copyright (C)  Rafal Szczesniak 2007
 */

/**
 * Swat Net Manager class graphical user interface
 */
qx.OO.defineClass("swat.module.netmgr.Gui", qx.core.Object,
function()
{
  qx.core.Object.call(this);
});


//qx.OO.addProperty({ name : "_tree", type : "object" });
//qx.OO.addProperty({ name : "_panel", type : "object" });

qx.Proto.buildGui = function(module)
{
  var fsm = module.fsm;

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
  
  panel.set({
              top: 0,
              right: 20,
              width: "80%",
              height: "100%"
            });
  
  // Add the tree view and panel for list view to the layout
  hlayout.add(tree);
  hlayout.add(panel);

  var statusLayout = new qx.ui.layout.HorizontalBoxLayout();
  statusLayout.set({
                     top: 0,
                     left: 0,
                     right: 0,
                     height: "100%"
                   });

  var vlayout = new qx.ui.layout.VerticalBoxLayout();
  vlayout.set({
                top: 20,
                left: 20,
                width: "100%",
                bottom: 20
              });

  vlayout.add(hlayout);
  vlayout.add(statusLayout);

  vlayout.addEventListener("appear", fsm.eventListener, fsm);
  fsm.addObject("vlayout", vlayout);

  module.canvas.add(vlayout);
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
  hostNode.credentials = undefined;
  hostNode.local = local
};


qx.Proto._initNetContext = function(module, rpcRequest)
{
  // Gather obtained NetContext handle
  var result = rpcRequest.getUserData("result").data;
  module.netCtx = result;
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
