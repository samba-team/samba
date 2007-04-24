/*
 * Copyright (C)  Rafal Szczesniak 2007
 */

/**
 * Swat Net Manager class finite state machine
 */
qx.OO.defineClass("swat.module.netmgr.Fsm", swat.main.AbstractModuleFsm,
function()
{
  swat.main.AbstractModuleFsm.call(this);
});


qx.Proto.buildFsm = function(module)
{
  var fsm = module.fsm;
  var _this = this;

  /*
   * State: Idle
   *
   * Actions upon entry
   *   - if returning from RPC, display the result
   *
   * Transition on:
   *   "changeselection" on tree
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "onentry" :
        function(fsm, event)
	{
	  if (fsm.getPreviousState() == "State_AwaitRpcResult")
	  {
	    var rpcRequest = _this.popRpcRequest();
	    var result = rpcRequest.getUserData("result");
	    var origins = swat.main.AbstractModuleFsm.JsonRpc_Origin;
	    var serverErrors = swat.main.AbstractModuleFsm.JsonRpc_ServerError;

	    if (result.type == "failed" &&
		result.data.origin == origins.Server &&
		result.data.code == serverErrors.ResourceError)
	    {
	      alert("Error when receiving rpc: '" + result.id + "'" + " exception: " + result.data);
	    }
	    else
	    {
	      // get the result of the call and apply it
              var gui = swat.module.netmgr.Gui.getInstance();
	      gui.displayData(module, rpcRequest);
	    }
	    
	    rpcRequest.request.dispose();
	    rpcRequest.request = null;
	  }
	},

      "events" :
        {
          "appear" :
          {
            "swat.main.canvas" :
              "Transition_Idle_to_AwaitRpcResult_via_canvas_appear",
            "vlayout":
              "Transition_Idle_to_AwaitRpcResult_via_vlayout_appear"
          },

	  "changeSelection" :
	  {
	    "tree" :
	      "Transition_Idle_to_Idle_via_tree_selection_changed"
          },

          "changeSelected":
          {
            // this one is dispatched from UsersView widget
	    "domainName":
              "Transition_Idle_to_AwaitRpcResult_via_domainName_changed"
          },
	 
	  "changeNetCtx" :
	  {
	    "swat.module.netmgr.Gui" :
	      "Transition_Idle_to_AwaitRpcResult_via_netCtx_changed"
	  }
        }
    });

  // Replace the initial Idle state with this one
  fsm.replaceState(state, true);

  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_canvas_appear",
    {
      "nextState" : "State_AwaitRpcResult",

      "ontransition" : function(fsm, event)
      {
	// Create default NetContext
        var request = _this.callRpc(fsm, "samba.ejsnet", "NetContext", []);
	request.setUserData("requestType", "NetContext");
      }
    });

  // Add the new transition
  state.addTransition(trans);

  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_vlayout_appear",
    {
      "nextState" : "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
	  // Request our netbios name to add proper node to the tree
	  var request = _this.callRpc(fsm, "samba.config", "lp_get", [ "netbios name" ]);
	  request.setUserData("requestType", "hostname");
        }
    });

  // Add the new transition
  state.addTransition(trans);

  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_via_tree_selection_changed",
    {
      "nextState" : "State_Idle",

      "ontransition" : function(fsm, event)
      {
	var nodes = event.getData();
	var selectedNode = nodes[0];

	var gui = swat.module.netmgr.Gui.getInstance();
	var parentNode = gui.getParentNode(module, selectedNode);

	// Change current NetContext if necessary for this host
	if (parentNode.netCtx != undefined)
        {
	  module.setNetCtx(parentNode.netCtx);
	}
	
	var domainName = parentNode.label;
	var nodeName = selectedNode.label;

	switch (nodeName)
        {
	case "Users":
	  gui.openUserManager(module, domainName);
	  break;

	case "Groups":
	case "Domain":
	case "Services":
	  alert("View not implemented yet");
	  break;

	default:
	  alert("Undefined call selected for node=['" + nodeName + "']");
	}
      }
      
    });

  // Add the new transition
  state.addTransition(trans);

  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_domainName_changed",
    {
      "nextState" : "State_AwaitRpcResult",

      "ontransition" : function(fsm, event)
      {
	var domainName = fsm.getObject("domainName").getValue();
	var netCtxId = swat.module.netmgr.Gui.getInstance().getNetCtx();
	
	var req = _this.callRpc(fsm, "samba.ejsnet", "UserMgr", [ netCtxId, domainName ]);
	req.setUserData("requestType", "UserMgr");
      }
    });

  // Add the new transition
  state.addTransition(trans);
  
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_netCtx_changed",
    {
      "nextState" : "State_AwaitRpcResult",

      "ontransition" : function(fsm, event)
      {
	var netCtxId = swat.module.netmgr.Gui.getInstance().getNetCtx();

	var req = _this.callRpc(fsm, "samba.ejsnet", "NetContextCreds", [ netCtxId ]);
	req.setUserData("requestType", "NetContextCreds");
      }
    });

  state.addTransition(trans);

  blockedEvents =
  {
    "appear":
    {
      "tree" : qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED,
      "vlayout" : qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED
    }
  }

  // Add blocked events
  this.addAwaitRpcResultState(module, blockedEvents);
  
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
