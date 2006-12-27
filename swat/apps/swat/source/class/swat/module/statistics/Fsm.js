/*
 * Copyright:
 *   (C) 2006 by Derrell Lipman
 *       All rights reserved
 *
 * License:
 *   LGPL 2.1: http://creativecommons.org/licenses/LGPL/2.1/
 */

/**
 * Swat statistics class finite state machine
 */
qx.OO.defineClass("swat.module.statistics.Fsm", swat.module.AbstractModuleFsm,
function()
{
  swat.module.AbstractModuleFsm.call(this);
});


qx.Class._startTimer = function(fsm)
{
  // Create a timer instance to expire in a few seconds
  var timer = new qx.client.Timer(5000);
  timer.addEventListener("interval", fsm.eventListener, fsm);
  fsm.addObject("timer", timer);
  timer.start();
};


qx.Class._stopTimer = function(fsm)
{
  // ... then stop the timer.  Get the timer object.
  var timer = fsm.getObject("timer");
            
  // If it still exists...
  if (timer)
  {
    // ... then dispose of it.
    timer.dispose();
    fsm.removeObject("timer");
  }
};


qx.Proto.buildFsm = function(module)
{
  var fsm = module.fsm;
  var thisClass = this;

  /*
   * State: Idle
   *
   * Actions upon entry
   *   - if returning from RPC, display the result
   *   - start an interval timer to request statistics again in a while
   *
   * Transition on:
   *  "interval" on interval_timer
   */
  var state = new qx.util.fsm.State(
    "State_Idle",
    {
      "onentry" :
        function(fsm, state)
        {
          // Did we just return from an RPC request?
          if (fsm.getPreviousState() == "State_AwaitRpcResult")
          {
            // Yup.  Display the result.  We need to get the request object
            var request = fsm.getObject("swat.module.fsmUtils.request");

            // We don't need the request object to be saved any more
            fsm.removeObject("swat.module.fsmUtils.request");

            // Display the result
            var gui = swat.module.statistics.Gui.getInstance();
            gui.displayData(module, request.result);

            // Dispose of the request (and result)
            request.result = null;
            request = null;

            // Restart the timer.
            swat.module.statistics.Fsm._startTimer(fsm);
          }
        },

      "onexit" :
        function(fsm, state)
        {
          // If we're not coming right back into this state...
          if (fsm.getNextState() != "State_Idle")
          {
            // ... then stop the timer.
            swat.module.statistics.Fsm._stopTimer(fsm);
          }
        },

      "events" :
        {
          // If the timer expires, send a new statistics request
          "interval" :
          {
            "timer" :
              "Transition_Idle_to_AwaitRpcResult_via_request_statistics"
          },

          // When we get an appear event, start our timer
          "appear" :
          {
            "swat.module.canvas" :
              "Transition_Idle_to_Idle_via_appear"
          },

          // When we get a disappear event, stop our timer
          "disappear" :
          {
            "swat.module.canvas" :
              "Transition_Idle_to_Idle_via_disappear"
          }
        }
    });

  // Replace the initial Idle state with this one
  fsm.replaceState(state, true);
  
  /*
   * Transition: Idle to AwaitRpcResult
   *
   * Cause: "interval" on timer
   *
   * Action:
   *  Issue a Get Statistics request
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_AwaitRpcResult_via_request_statistics",
    {
      "nextState" :
        "State_AwaitRpcResult",

      "ontransition" :
        function(fsm, event)
        {
          var rpc = fsm.getObject("swat.module.rpc");

          rpc.setUrl("/services/");
          rpc.setServiceName("samba.management");

          var request =
            rpc.callAsyncListeners(true, // coalesce failure events
                                   "get_statistics",
                                   true, true);
          fsm.addObject("swat.module.fsmUtils.request", request);
        }
    });
  state.addTransition(trans);

  /*
   * Transition: Idle to Idle
   *
   * Cause: "appear" on canvas
   *
   * Action:
   *  Start our timer
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_via_appear",
    {
      "nextState" :
        "State_Idle",

      "ontransition" :
        function(fsm, event)
        {
          swat.module.statistics.Fsm._startTimer(fsm);
        }
    });
  state.addTransition(trans);

  /*
   * Transition: Idle to Idle
   *
   * Cause: "disappear" on canvas
   *
   * Action:
   *  Stop our timer
   */
  var trans = new qx.util.fsm.Transition(
    "Transition_Idle_to_Idle_via_disappear",
    {
      "nextState" :
        "State_Idle",

      "ontransition" :
        function(fsm, event)
        {
          swat.module.statistics.Fsm._stopTimer(fsm);
        }
    });
  state.addTransition(trans);

  // Add the AwaitRpcResult state and all of its transitions
  this.addAwaitRpcResultState(module);

  // Allocate an RPC object
  o = new qx.io.remote.Rpc();
  o.setTimeout(10000);
  o.addEventListener("completed", fsm.eventListener, fsm);
  o.addEventListener("failed", fsm.eventListener, fsm);
  o.addEventListener("timeout", fsm.eventListener, fsm);
  o.addEventListener("aborted", fsm.eventListener, fsm);
  fsm.addObject("swat.module.rpc", o);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
