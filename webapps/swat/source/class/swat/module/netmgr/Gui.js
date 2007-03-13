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

qx.Proto.buildGui = function(module)
{
  var fsm = module.fsm;

  // We need a horizontal box layout for the database name
  var vlayout = new qx.ui.layout.VerticalBoxLayout();
  vlayout.set({
                  top: 20,
                  left: 20,
                  right: 20,
                  bottom: 20
              });
  
  // Create a hosts tree
  this._tree = new qx.ui.treevirtual.TreeVirtual(["Net"]);
  var tree = this._tree;

  // Set the tree's properties
  tree.set({
             backgroundColor: 255,
	     border: qx.renderer.border.BorderPresets.getInstance().thinInset,
             overflow: "hidden",
             width: "30%",
             height: "1*",
             alwaysShowOpenCloseSymbol: true
           });

  tree.setCellFocusAttributes({ backgroundColor : "transparent" });

  // Create event listener
  tree.addEventListener("appear", fsm.eventListener, fsm);

  // Give a tree widget nicer name to handle
  fsm.addObject("tree", tree, "swat.main.fsmUtils.disable_during_rpc");
  
  // Add the label to the horizontal layout
  vlayout.add(tree);

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
      this._addHostNode(module, rpcRequest);
      break;

    case "NetContext":
      this._initNetContext(module, rpcRequest);
      break;
  }

  qx.ui.core.Widget.flushGlobalQueues();
};


qx.Proto._addHostNode = function(module, rpcRequest)
{
  var fsm = module.fsm;
  var hostname = rpcRequest.getUserData("result").data;

  // Get the tree widget
  var tree = this._tree;
  var dataModel = tree.getDataModel();

  // Add new host and its service branches
  var hostNodeId = dataModel.addBranch(null, hostname, false);
  
  var domainNodeId = dataModel.addBranch(hostNodeId, "Domain", false);
  var usersNodeId = dataModel.addBranch(hostNodeId, "Users", false);
  var groupsNodeId = dataModel.addBranch(hostNodeId, "Groups", false);
  var srvcsNodeId = dataModel.addBranch(hostNodeId, "Services", false);

  // Services don't expand
  dataModel.setState(domainNodeId, { bHideOpenClose : true });
  dataModel.setState(usersNodeId, { bHideOpenClose : true });
  dataModel.setState(groupsNodeId, { bHideOpenClose : true });
  dataModel.setState(srvcsNodeId, { bHideOpenClose : true });
  
  dataModel.setData();
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
