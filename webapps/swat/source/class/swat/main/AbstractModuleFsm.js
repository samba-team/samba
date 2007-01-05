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
qx.OO.defineClass("swat.main.AbstractModuleFsm", qx.core.Object, function()
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
   *  - enable any objects in group "swat.main.fsmUtils.enable_during_rpc"
   *  - disable any objects in group "swat.main.fsmUtils.disable_during_rpc"
   *
   * Actions upon exit:
   *   - disable any objects in group "swat.main.fsmUtils.enable_during_rpc"
   *   - enable any objects in group "swat.main.fsmUtils.disable_during_rpc"
   *
   * Transition on:
   *  "completed" (on RPC)
   *  "failed" (on RPC)
   *  "execute" on swat.main.fsmUtils.abort_rpc
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
            // swat.main.fsmUtils.enable_during_rpc
            "parameters" : [ true ],

            // Call this.getObject(<object>).setEnabled(true) on
            // state entry, for each <object> in the group called
            // "swat.main.fsmUtils.enable_during_rpc".
            "groups"      : [ "swat.main.fsmUtils.enable_during_rpc" ]
          },

          {
            // We want to disable objects in the group
            // swat.main.fsmUtils.disable_during_rpc
            "parameters" : [ false ],

            // Call this.getObject(<object>).setEnabled(false) on
            // state entry, for each <object> in the group called
            // "swat.main.fsmUtils.disable_during_rpc".
            "groups"      : [ "swat.main.fsmUtils.disable_during_rpc" ]
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
            // swat.main.fsmUtils.enable_during_rpc
            "parameters" : [ false ],

            // Call this.getObject(<object>).setEnabled(false) on
            // state entry, for each <object> in the group called
            // "swat.main.fsmUtils.enable_during_rpc".
            "groups"      : [ "swat.main.fsmUtils.enable_during_rpc" ]
          },

          {
            // We want to re-enable objects we had disabled, in the group
            // swat.main.fsmUtils.disable_during_rpc
            "parameters" : [ true ],

            // Call this.getObject(<object>).setEnabled(true) on
            // state entry, for each <object> in the group called
            // "swat.main.fsmUtils.disable_during_rpc".
            "groups"      : [ "swat.main.fsmUtils.disable_during_rpc" ]
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
          "swat.main.fsmUtils.abort_rpc" :
            "Transition_AwaitRpcResult_to_AwaitRpcResult_via_button_abort"
        },

        "completed" :
          "Transition_AwaitRpcResult_to_PopStack_via_complete",

        "failed" :
          qx.util.fsm.FiniteStateMachine.EventHandling.PREDICATE
      }
    });
  fsm.addState(state);

  /*** Transitions that use a PREDICATE appear first ***/

  /*
   * Transition: AwaitRpcResult to GetAuthInfo
   *
   * Cause: "failed" (on RPC) where reason is PermissionDenied
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_GetAuthInfo",
    {
      "nextState" :
        qx.util.fsm.FiniteStateMachine.StateChange.POP_STATE_STACK,

      "predicate" :
        function(fsm, event)
        {
          var error = event.getData(); // retrieve the JSON-RPC error

          // Did we get get origin=Server, code=PermissionDenied ?
          var origins = swat.main.AbstractModuleFsm.JsonRpc_Origin;
          var serverErrors = swat.main.AbstractModuleFsm.JsonRpc_ServerError;
          if (error.origin == origins.Server &&
              error.code == serverErrors.PermissionDenied)
          {
            return true;
          }

          // fall through to next transition, also for "failed"
          return false;
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

  /*** Remaining transitions are accessed via the jump table ***/

  /*
   * Transition: AwaitRpcResult to AwaitRpcResult
   *
   * Cause: "execute" on swat.main.fsmUtils.abort_rpc
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
  var rpc = fsm.getObject("swat.main.rpc");

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


/**
 * JSON-RPC error origins
 */
qx.Class.JsonRpc_Origin =
{
  Server              : 1,
  Application         : 2,
  Transport           : 3,
  Client              : 4
};


/**
 * JSON-RPC Errors for origin == Server
 */
qx.Class.JsonRpc_ServerError =
{
  /**
   * Error code, value 0: Unknown Error
   *
   * The default error code, used only when no specific error code is passed
   * to the JsonRpcError constructor.  This code should generally not be used.
   */
  Unknown               : 0,

  /**
   * Error code, value 1: Illegal Service
   *
   * The service name contains illegal characters or is otherwise deemed
   * unacceptable to the JSON-RPC server.
   */
  IllegalService        : 1,

  /**
   * Error code, value 2: Service Not Found
   *
   * The requested service does not exist at the JSON-RPC server.
   */
  ServiceNotFound       : 2,

  /**
   * Error code, value 3: Class Not Found
   *
   * If the JSON-RPC server divides service methods into subsets (classes),
   * this indicates that the specified class was not found.  This is slightly
   * more detailed than "Method Not Found", but that error would always also
   * be legal (and true) whenever this one is returned. (Not used in this
   * implementation)
   */
  ClassNotFound         : 3, // not used in this implementation

  /**
   * Error code, value 4: Method Not Found
   *
   * The method specified in the request is not found in the requested
   * service.
   */
  MethodNotFound        : 4,

  /*
   * Error code, value 5: Parameter Mismatch
   *
   * If a method discovers that the parameters (arguments) provided to it do
   * not match the requisite types for the method's parameters, it should
   * return this error code to indicate so to the caller.
   *
   * This error is also used to indicate an illegal parameter value, in server
   * scripts.
   */
  ParameterMismatch     : 5,

  /**
   * Error code, value 6: Permission Denied
   *
   * A JSON-RPC service provider can require authentication, and that
   * authentication can be implemented such the method takes authentication
   * parameters, or such that a method or class of methods requires prior
   * authentication.  If the caller has not properly authenticated to use the
   * requested method, this error code is returned.
   */
  PermissionDenied      : 6,

  /*
   * Error code, value 7: Unexpected Output
   *
   * The called method illegally generated output to the browser, which would
   * have preceeded the JSON-RPC data.
   */
  UnexpectedOutput      : 7,

  /*
   * Error code, value 8: Resource Error
   *
   * Too many resources were requested, a system limitation on the total
   * number of resources has been reached, or a resource or resource id was
   * misused.
   */
  ResourceError         : 8

};
