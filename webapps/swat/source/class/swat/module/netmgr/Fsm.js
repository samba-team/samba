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
	      this.debug("error" + result);
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
              "Transition_Idle_to_AwaitRpcResult_via_canvas_appear"
          }
        }
    });

  // Replace the initial Idle state with this one
  fsm.replaceState(state, true);

  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_canvas_appear",
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

  blockedEvents =
  {
    "appear":
    {
      "tree" : qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED
    }
  }

  this.addAwaitRpcResultState(module, blockedEvents);
  
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.lang.Function.returnInstance;
