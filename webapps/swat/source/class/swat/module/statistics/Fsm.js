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
qx.OO.defineClass("swat.module.statistics.Fsm", swat.main.AbstractModuleFsm,
function()
{
  swat.main.AbstractModuleFsm.call(this);
});


/**
 * Start the redisplay timer.
 *
 * @param fsm {qx.util.fsm.FiniteStateMachine}
 *   The finite state machine in use by this module
 *
 * @param msInterval {Integer}
 *   The number of milliseconds before the timer should expire
 */
qx.Class._startTimer = function(fsm, msInterval)
{

  // First, for good house keeping, ensure no timer exists
  swat.module.statistics.Fsm._stopTimer(fsm);

  // Create a timer instance to expire in a few seconds
  var timer = new qx.client.Timer(msInterval);
  timer.addEventListener("interval", fsm.eventListener, fsm);
  fsm.addObject("timer", timer);
  timer.start();
};


/**
 * Stop the redisplay timer.
 *
 * @param fsm {qx.util.fsm.FiniteStateMachine}
 *   The finite state machine in use by this module
 */
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
  var _this = this;
  var _module = module;

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
        function(fsm, event)
        {
          // Did we just return from an RPC request?
          if (fsm.getPreviousState() == "State_AwaitRpcResult")
          {
            // Yup.  Display the result.  We need to get the request object
            var rpcRequest = _this.popRpcRequest();

            // Display the result
            var gui = swat.module.statistics.Gui.getInstance();
            gui.displayData(module, rpcRequest.getUserData("result"));

            // Dispose of the request
            rpcRequest.request.dispose();
            rpcRequest.request = null;

            // Restart the timer.
            if (_module.visible)
            {
              // Give it a reasonable interval before we redisplay
              swat.module.statistics.Fsm._startTimer(fsm, 5000);
            }
          }
        },

      "onexit" :
        function(fsm, event)
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
            "swat.main.canvas" :
              "Transition_Idle_to_Idle_via_appear"
          },

          // When we get a disappear event, stop our timer
          "disappear" :
          {
            "swat.main.canvas" :
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
          // Issue a Get Statistics call
          _this.callRpc(fsm,
                        "samba.management",
                        "get_statistics",
                        [ true, true ]);
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
          _module.visible = true;

          // Redisplay immediately
          swat.module.statistics.Fsm._startTimer(fsm, 0);
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
          _module.visible = false;
          swat.module.statistics.Fsm._stopTimer(fsm);
        }
    });
  state.addTransition(trans);

  // Add the AwaitRpcResult state and all of its transitions
  this.addAwaitRpcResultState(module);
};


/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
