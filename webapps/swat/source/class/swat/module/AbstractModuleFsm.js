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
          var rpcRequest = _this.getCurrentRpcRequest();

          // Issue an abort for the pending request
          rpcRequest.request.abort();
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
          var rpcRequest = _this.getCurrentRpcRequest();
          
          // Generate the result for a completed request
          rpcRequest.setUserData("result",
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
          var rpcRequest = _this.getCurrentRpcRequest();
          
          // Generate the result for a completed request
          rpcRequest.setUserData("result",
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
 * @param service {string}
 *   The name of the remote service which provides the specified method.
 *
 * @param method {string}
 *   The name of the method within the specified service.
 *
 * @param params {Array}
 *   The parameters to be passed to the specified method.
 *
 * @return {Object}
 *   The request object for the just-issued RPC request.
 */
qx.Proto.callRpc = function(fsm, service, method, params)
{
  // Create an object to hold a copy of the parameters.  (We need a
  // qx.core.Object() to be able to store this in the finite state machine.)
  var rpcRequest = new qx.core.Object();

  // Save the service name
  rpcRequest.service = service;

  // Copy the parameters; we'll prefix our copy with additional params
  rpcRequest.params = params.slice(0);

  // Prepend the method
  rpcRequest.params.unshift(method);

  // Prepend the flag indicating to coalesce failure events
  rpcRequest.params.unshift(true);

  // Retrieve the RPC object */
  var rpc = fsm.getObject("swat.module.rpc");

  // Set the service name
  rpc.setServiceName(rpcRequest.service);

  // Issue the request, skipping the already-specified service name
  rpcRequest.request =
    qx.io.remote.Rpc.prototype.callAsyncListeners.apply(rpc,
                                                        rpcRequest.params);

  // Make the rpc request object available to the AwaitRpcResult state
  this.pushRpcRequest(rpcRequest);

  // Give 'em what they came for
  return rpcRequest;
};


/**
 * Push an RPC request onto the request stack.
 *
 * @param request {Object}
 *   The just-issued rpc request object
 */
qx.Proto.pushRpcRequest = function(rpcRequest)
{
  this._requests.push(rpcRequest);
};


/**
 * Retrieve the most recent RPC request from the request stack and pop the
 * stack.
 *
 * @return {Object}
 *   The rpc request object from the top of the request stack
 */
qx.Proto.popRpcRequest = function()
{
  if (this._requests.length == 0)
  {
    throw new Error("Attempt to pop an RPC request when list is empty.");
  }

  var rpcRequest = this._requests.pop();
  return rpcRequest;
};


/**
 * Retrieve the most recent RPC request.
 *
 * @return {Object}
 *   The rpc request object at the top of the request stack
 */
qx.Proto.getCurrentRpcRequest = function()
{
  if (this._requests.length == 0)
  {
    throw new Error("Attempt to retrieve an RPC request when list is empty.");
  }

  return this._requests[this._requests.length - 1];
};

