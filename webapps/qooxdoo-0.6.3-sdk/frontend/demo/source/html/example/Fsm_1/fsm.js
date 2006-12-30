/*
 * Initialize the finite state machine.
 *
 * This finite state machine has two states: Idle and AwaitRpcResult.
 *
 * In the Idle state, the Send button is enabled, the Abort button is
 * disabled, and the three color bars are blue.  In the AwaitRpcResult state,
 * the Send button is disabled, the Abort button is enabled, and three color
 * bars are red.  All of these changes occur via automatic, table-driven
 * function calls in autoActionsXXX() objects, not via explicit code.  This
 * demonstrates how groups of objects can all be manipulated together without
 * having to write lots of code to do so.  Just as these color blocks change
 * color, numerous widgets could be disabled/hidden/etc., without writing code
 * to futz with all of them.
 */
function initFsm()
{
  // Create a new finite state machine
  var fsm = new qx.util.fsm.FiniteStateMachine("Fsm_1");

  // For this simple example application, show all debug messages.
  qx.Settings.setCustomOfClass(
    "qx.util.fsm.FiniteStateMachine",
    "debugFlags",
    (qx.util.fsm.FiniteStateMachine.DebugFlags.EVENTS |
     qx.util.fsm.FiniteStateMachine.DebugFlags.TRANSITIONS |
     qx.util.fsm.FiniteStateMachine.DebugFlags.FUNCTION_DETAIL |
     qx.util.fsm.FiniteStateMachine.DebugFlags.OBJECT_NOT_FOUND));

  /*
   * State: Idle
   *
   * Actions upon entry:
   *  button_send.setEnabled(true);
   *  button_abort.setEnabled(false);
   *  change background of objects in group "group_color_change" to blue
   *
   * Transition on:
   *  "execute" on button_send
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "autoActionsBeforeOnentry" :
      {
        // The name of a function.
        "setEnabled" :
        [
          {
            // We want to enable the 'send' button
            "parameters" : [ true ],

            // Call this.getObject("button_send").setEnabled(true)
            "objects"    : [ "button_send" ]
          },

          {
            // We want to disable the 'abort' button
            "parameters" : [ false ],

            // Call this.getObject("button_abort").setEnabled(false)
            "objects"    : [ "button_abort" ]
          }
        ],

        // The name of a function.
        "setBackgroundColor" :
        [
          {
            // We want to change the atoms' background color to blue
            "parameters" :
              [
               // We want the color oject created when needed, not "now"
               // Providing a function as a parameter allows the value to be
               // determined later.
               function (fsm) { return new qx.renderer.color.Color("blue"); }
              ],

            // Call this.getObject(<object>).seBackgroundcolor("blue") on
            // state entry, for each <object> in the group called
            // "group_color_change".
            "groups"      : [ "group_color_change" ]
          }
        ]
      },

      "events" :
        {
          // If the send button is pressed, go to new state state where we
          // will await the RPC result
          "execute"  :
          {
            "button_send" :
              "Transition_Idle_to_AwaitRpcResult_via_button_send"
          }
        }
    });
  fsm.addState(state);

  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "execute" on button_send
   *
   * Action:
   *  Issue RPC request with coalesced failure events
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_button_send",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          var rpc = fsm.getObject("rpc");

          rpc.setUrl(fsm.getObject("text_url").getValue());
          rpc.setServiceName(fsm.getObject("text_service").getValue());

          var request =
            rpc.callAsyncListeners(true, // coalesce failure events
                                   fsm.getObject("text_method").getValue(),
                                   fsm.getObject("text_message").getValue());
          fsm.addObject("request", request);
        }
    });
  state.addTransition(trans);


  /*
   * State: AwaitRpcResult
   *
   * Actions upon entry:
   *  button_send.setEnabled(false);
   *  button_abort.setEnabled(true);
   *  change background of objects in group "group_color_change" to red
   *
   * Transition on:
   *  "completed" (on RPC)
   *  "failed" (on RPC)
   *  "execute on button_abort
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
            // We want to disable the 'send' button
            "parameters" : [ false ],
              
            // Call this.getObject("send").setEnabled(false)
            "objects"    : [ "button_send" ]
          },

          {
            // We want to enable the 'abort' button
            "parameters" : [ true ],

            // Call this.getObject("abort").setEnabled(true)
            "objects" : [ "button_abort" ]
          }
        ],

        // The name of a function.
        "setBackgroundColor" :
        [
          {
            // We want to change the atoms' background color to red
            "parameters" :
               [
                 // We want the color oject created when needed, not "now"
                 // Providing a function as a parameter allows the value to be
                 // determined later.
                 function (fsm) { return new qx.renderer.color.Color("red"); }
               ],

            // Call this.getObject(<object>).seBackgroundcolor("red"), for
            // each <object> in the group called "group_color_change".
            "groups" : [ "group_color_change" ]
          }
        ]
      },

      "events" :
      {
        "execute"  :
        {
          "button_abort" :
            "Transition_AwaitRpcResult_to_AwaitRpcResult_via_button_abort"
        },

        "completed" :
          "Transition_AwaitRpcResult_to_Idle_via_complete",

        "failed" :
          "Transition_AwaitRpcResult_to_Idle_via_failed"
      },

      "onentry" :
        function(fsm, state)
        {
          var message = fsm.getObject("text_result");
          message.setValue("");
        }

    });
  fsm.addState(state);

  /*
   * Transition: AwaitRpcResult to AwaitRpcResult
   *
   * Cause: "execute" on button_abort
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
          var request = fsm.getObject("request");

          // Issue an abort for the pending request
          request.abort();
          
          var message = fsm.getObject("text_result");
          message.setValue("Abort requested...");
        }
    });
  state.addTransition(trans);

  /*
   * Transition: AwaitRpcResult to Idle
   *
   * Cause: "complete" (on RPC)
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_Idle_via_complete",
    {
      "nextState" :
        "State_Idle",

      "ontransition" :
        function(fsm, event)
        {
          var message = fsm.getObject("text_result");
          message.setValue("Got result: " + event.getData());

          // The request has completed, so remove the object reference
          fsm.removeObject("request");
        }
    });
  state.addTransition(trans);

  /*
   * Transition: AwaitRpcResult to Idle
   *
   * Cause: "failed" (on RPC)
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_AwaitRpcResult_to_Idle_via_failed",
    {
      "nextState" :
        "State_Idle",

      "ontransition" :
        function(fsm, event)
        {
          var message = fsm.getObject("text_result");
          message.setValue("Got failure: " + event.getData());

          // The request has completed, so remove the object reference
          fsm.removeObject("request");
        }
    });
  state.addTransition(trans);

  // Allocate an RPC object
  o = new qx.io.remote.Rpc();
  o.setTimeout(10000);
  o.addEventListener("completed", fsm.eventListener, fsm);
  o.addEventListener("failed", fsm.eventListener, fsm);
  o.addEventListener("timeout", fsm.eventListener, fsm);
  o.addEventListener("aborted", fsm.eventListener, fsm);
  fsm.addObject("rpc", o);

  return fsm;
}
