/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Common facilities for modules' finite state machines.  Each module's FSM
 * should extend this class.
 */
qx.OO.defineClass("swat.module.AbstractModuleFsm", qx.core.Object, function()
{
  qx.core.Object.call(this);

  // Create an array for pushing request objects
  this._requests = [ ];
});


qx.Proto.buildFsm = function(module)
{
  throw new Error("Module must overload buildFsm() " +
                  "to build its custom finite state machine.");
};

qx.Proto.addAwaitRpcResultState = function(module)
{
  var fsm = module.fsm;
  var _this = this;

  /*
   * State: AwaitRpcResult
   *
   * Actions upon entry:
   *  - enable any objects in group "swat.module.fsmUtils.enable_during_rpc"
   *  - disable any objects in group "swat.module.fsmUtils.disable_during_rpc"
   *
   * Actions upon exit:
   *   - disable any objects in group "swat.module.fsmUtils.enable_during_rpc"
   *   - enable any objects in group "swat.module.fsmUtils.disable_during_rpc"
   *
   * Transition on:
   *  "completed" (on RPC)
   *  "failed" (on RPC)
   *  "execute" on swat.module.fsmUtils.abort_rpc
   */
  var state = new qx.util.fsm.State(
    "State_AwaitRpcResult",
    {
      "autoActionsBeforeOnentry" :
      {
        // The name of a function.
        "setEnabled" :
        [
          {
            // We want to enable objects in the group
            // swat.module.fsmUtils.enable_during_rpc
            "parameters" : [ true ],

            // Call this.getObject(<object>).setEnabled(true) on
            // state entry, for each <object> in the group called
            // "swat.module.fsmUtils.enable_during_rpc".
            "groups"      : [ "swat.module.fsmUtils.enable_during_rpc" ]
          },

          {
            // We want to disable objects in the group
            // swat.module.fsmUtils.disable_during_rpc
            "parameters" : [ false ],

            // Call this.getObject(<object>).setEnabled(false) on
            // state entry, for each <object> in the group called
            // "swat.module.fsmUtils.disable_during_rpc".
            "groups"      : [ "swat.module.fsmUtils.disable_during_rpc" ]
          }
        ]
      },

      "autoActionsBeforeOnexit" :
      {
        // The name of a function.
        "setEnabled" :
        [
          {
            // We want to re-disable objects we had enabled, in the group
            // swat.module.fsmUtils.enable_during_rpc
            "parameters" : [ false ],

            // Call this.getObject(<object>).setEnabled(false) on
            // state entry, for each <object> in the group called
            // "swat.module.fsmUtils.enable_during_rpc".
            "groups"      : [ "swat.module.fsmUtils.enable_during_rpc" ]
          },

          {
            // We want to re-enable objects we had disabled, in the group
            // swat.module.fsmUtils.disable_during_rpc
            "parameters" : [ true ],

            // Call this.getObject(<object>).setEnabled(true) on
            // state entry, for each <object> in the group called
            // "swat.module.fsmUtils.disable_during_rpc".
            "groups"      : [ "swat.module.fsmUtils.disable_during_rpc" ]
          }
        ]
      },

      "onentry" :
        function(fsm, state)
        {
          // If we're coming from some other state...
          if (fsm.getPreviousState() != "State_AwaitRpcResult")
          {
            // ... then push the previous state onto the state stack
            fsm.pushState(false);
          }
        },

      "events" :
      {
        "execute"  :
        {
          "swat.module.fsmUtils.abort_rpc" :
            "Transition_AwaitRpcResult_to_AwaitRpcResult_via_button_abort"
        },

        "completed" :
          "Transition_AwaitRpcResult_to_PopStack_via_complete",

        "failed" :
          "Transition_AwaitRpcResult_to_PopStack_via_failed"
      }
    });
  fsm.addState(state);

  /*
   * Transition: AwaitRpcResult to AwaitRpcResult
   *
   * Cause: "execute" on swat.module.fsmUtils.abort_rpc
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_AwaitRpcResult_via_button_abort",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          // Get the request object
          var request = _this.getCurrentRpcRequest();

          // Issue an abort for the pending request
          request.abort();
        }
    });
  state.addTransition(trans);

  /*
   * Transition: AwaitRpcResult to PopStack
   *
   * Cause: "complete" (on RPC)
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_PopStack_via_complete",
    {
      "nextState" :
        qx.util.fsm.FiniteStateMachine.StateChange.POP_STATE_STACK,

      "ontransition" :
        function(fsm, event)
        {
          // Get the request object
          var request = _this.getCurrentRpcRequest();
          
          // Generate the result for a completed request
          request.setUserData("result",
                              {
                                  type : "complete",
                                  data : event.getData()
                              });
        }
    });
  state.addTransition(trans);

  /*
   * Transition: AwaitRpcResult to PopStack
   *
   * Cause: "failed" (on RPC)
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_PopStack_via_failed",
    {
      "nextState" :
        qx.util.fsm.FiniteStateMachine.StateChange.POP_STATE_STACK,

      "ontransition" :
        function(fsm, event)
        {
          // Get the request object
          var request = _this.getCurrentRpcRequest();
          
          // Generate the result for a completed request
          request.setUserData("result",
                              {
                                  type : "failed",
                                  data : event.getData()
                              });
        }
    });
  state.addTransition(trans);
};


/**
 * Issue a remote procedure call.
 *
 * @param fsm {qx.util.fsm.FiniteStateMachine}
 *   The finite state machine issuing this remote procedure call.
 *
 * @param service {String}
 *   The name of the remote service which provides the specified method.
 *
 * @param method {String}
 *   The name of the method within the specified service.
 *
 * @param params {Array}
 *   The parameters to be passed to the specified method.
 *
 * @return {qx.io.remote.Request}
 *   The request object for the just-issued RPC request.
 */
qx.Proto.callRpc = function(fsm, service, method, params)
{
  // Create an object to hold a copy of the parameters.  (We need a
  // qx.core.Object() to be able to store this in the finite state machine.)
  var o = new qx.core.Object();

  // copy the parameters; we'll prefix our copy with additional params
  o.allParams = params.slice(0);

  // prepend the method
  o.allParams.unshift(method);

  // prepend the flag indicating to coalesce failure events
  o.allParams.unshift(true);

  // prepend the service name
  o.allParams.unshift(service);

  // Save the complete parameter list in case authentication fails and we need
  // to reissue the request.
  fsm.addObject("swat.module.rpc_params", o);
  
  // Retrieve the RPC object */
  var rpc = fsm.getObject("swat.module.rpc");

  // Set the service name
  rpc.setServiceName(o.allParams[0]);

  // Issue the request, skipping the already-specified service name
  var request =
    qx.io.remote.Rpc.prototype.callAsyncListeners.apply(rpc,
                                                        o.allParams.slice(1));

  // Make the request object available to the AwaitRpcResult state
  this.pushRpcRequest(request);

  // Give 'em what they came for
  return request;
};


/**
 * Push an RPC request onto the request stack.
 *
 * @param request {qx.io.remote.Request}
 *   The just-issued request
 */
qx.Proto.pushRpcRequest = function(request)
{
  this._requests.push(request);
};


/**
 * Retrieve the most recent RPC request from the request stack and pop the
 * stack.
 *
 * @return {qx.io.remote.Request}
 *   The request from the top of the request stack
 */
qx.Proto.popRpcRequest = function()
{
  if (this._requests.length == 0)
  {
    throw new Error("Attempt to pop an RPC request when list is empty.");
  }

  var request = this._requests.pop();
  return request;
};


/**
 * Retrieve the most recent RPC request.
 *
 * @return {qx.io.remote.Request}
 *   The request at the top of the request stack
 */
qx.Proto.getCurrentRpcRequest = function()
{
  if (this._requests.length == 0)
  {
    throw new Error("Attempt to retrieve an RPC request when list is empty.");
  }

  return this._requests[this._requests.length - 1];
};

