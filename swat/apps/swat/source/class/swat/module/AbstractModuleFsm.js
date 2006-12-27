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
});


qx.Proto.buildFsm = function(module)
{
  throw new Error("Module must overload buildFsm() " +
                  "to build its custom finite state machine.");
};

qx.Proto.addAwaitRpcResultState = function(module)
{
  var fsm = module.fsm;

  /*
   * State: AwaitRpcResult
   *
   * Actions upon entry:
   *  - enable any objects in group "swat.module.fsmUtils.enable_during_rpc"
   *  - disable any objects in group "swat.module.fsmUtils.disable_during_rpc"
   *
   * Actions upon exit:
   *   - disable any objects in group "group_enable_during_rpc"
   *   - enable any objects in group "group_disable_during_rpc"
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
          // If we're coming from some other start...
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
          var request = fsm.getObject("swat.module.fsmUtils.request");

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
          var request = fsm.getObject("swat.module.fsmUtils.request");
          
          // Generate the result for a completed request
          request.result =
          {
            type : "complete",
            data : event.getData()
          };
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
          var request = fsm.getObject("swat.module.fsmUtils.request");
          
          // Generate the result for a completed request
          request.result =
          {
            type : "failed",
            data : event.getData()
          };
        }
    });
  state.addTransition(trans);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
