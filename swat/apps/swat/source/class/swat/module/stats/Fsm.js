/**
 * Swat statistics class finite state machine
 */
qx.OO.defineClass("swat.module.stats.Fsm", swat.module.AbstractModuleFsm,
function()
{
  swat.module.AbstractModuleFsm.call(this);
});


qx.Proto.buildFsm = function(module)
{
  var fsm = module.fsm;

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

            // Get the message object
            var message = fsm.getObject("message");

            // Did the request succeed or fail?
            switch(request.result.type)
            {
            case "complete":
              // It succeeded
              message.setValue("Result: " + request.result.data);
              break;
              
            case "failed":
              // It failed
              message.setValue("Failed: " + request.result.data);
              break;
            }
          }

          // Create a timer instance to expire in 5 seconds
          var timer = new qx.client.Timer(5000);
          timer.addEventListener("interval", fsm.eventListener, fsm);
          fsm.addObject("timer", timer);
          timer.start();
        },

      "onexit" :
        function(fsm, state)
        {
          // Get the timer object
          var timer = fsm.getObject("timer");

          // If it still exists...
          if (timer)
          {
            // ... then dispose of it.
            timer.dispose();
            fsm.removeObject("timer");
          }
        },

      "events" :
        {
          // If the timer expires, send a new statistics request
          "interval"  :
          {
            "timer" :
              "Transition_Idle_to_AwaitRpcResult_via_request_statistics"
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
          rpc.setServiceName("samba.admin");

          var request =
            rpc.callAsyncListeners(true, // coalesce failure events
                                   "get_statistics");
          fsm.addObject("swat.module.fsmUtils.request", request);
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
