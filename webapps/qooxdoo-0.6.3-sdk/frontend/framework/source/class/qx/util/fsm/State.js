/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2006 by Derrell Lipman

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Derrell Lipman (derrell)

************************************************************************ */

/* ************************************************************************

#module(util_fsm)
#require(qx.util.fsm.FiniteStateMachine)

************************************************************************ */

/**
 * Create a new state which may be added to a finite state machine.
 *
 * *EXPERIMENTAL*
 * The interface to the finite state machine, states, and transitions is
 * experimental.  It may change in non-backward-compatible ways as more
 * experience is gained in its use.
 *
 * @param
 * stateName -
 *   The name of this state.  This is the name which may be referenced in
 *   objects of class qx.util.fsm.Transition, when passing of
 *   the the transition's predicate means transition to this state.
 *
 * @param
 * stateInfo -
 *   An object containing any of the following properties:
 *
 *     onentry -
 *       A function which is called upon entry to the state.  Its signature is
 *       function(fsm, event) and it is saved in the onentry property of the
 *       state object.  (This function is called after the Transition's action
 *       function and after the previous state's onexit function.)
 *
 *       In the onentry function:
 *
 *         fsm -
 *           The finite state machine object to which this state is attached.
 *
 *         event -
 *           The event that caused the finite state machine to run
 *
 *     onexit -
 *       A function which is called upon exit from the state.  Its signature
 *       is function(fsm, event) and it is saved in the onexit property of the
 *       state object.  (This function is called after the Transition's action
 *       function and before the next state's onentry function.)
 *
 *       In the onexit function:
 *
 *         fsm -
 *           The finite state machine object to which this state is attached.
 *
 *         event -
 *           The event that caused the finite state machine to run
 *
 *     autoActionsBeforeOnentry -
 *     autoActionsAfterOnentry -
 *     auutoActionsBeforeOnexit -
 *     autoActionsAfterOnexit -
 *       Automatic actions which take place at the time specified by the
 *       property name.  In all cases, the action takes place immediately
 *       before or after the specified function.
 *
 *       The property value for each of these properties is an object which
 *       describes some number of functions to invoke on a set of specified
 *       objects (typically widgets).
 *
 *       An example, using autoActionsBeforeOnentry, might look like this:
 *
 *       "autoActionsBeforeOnentry" :
 *       {
 *         // The name of a function.
 *         "enabled" :
 *         [
 *           {
 *             // The parameter value, thus "setEnabled(true);"
 *             "parameters" : [ true ],
 *
 *             // The function would be called on each object:
 *             //  this.getObject("obj1").setEnabled(true);
 *             //  this.getObject("obj2").setEnabled(true);
 *             "objects" : [ "obj1", "obj2" ],
 *
 *             // And similarly for each object in each specified group.
 *             "groups"  : [ "group1", "group2" ]
 *           }
 *         ],
 *
 *         // The name of another function.
 *         "visible" :
 *         [
 *           {
 *             // The parameter value, thus "setEnabled(true);"
 *             "parameters" : [ false ],
 *
 *             // The function would be called on each object and group, as
 *             // described above.
 *             "objects" : [ "obj3", "obj4" ],
 *             "groups"  : [ "group3", "group4" ]
 *           }
 *         ]
 *       };
 *
 *
 *     events (required) -
 *       A description to the finite state machine of how to handle a
 *       particular event, optionally associated with a specific target object
 *       on which the event was dispatched.  This should be an object
 *       containing one property for each event which is either handled or
 *       blocked.  The property name should be the event name.  The property
 *       value should be one of:
 *
 *         (a) qx.util.fsm.FiniteStateMachine.EventHandling.PREDICATE
 *
 *         (b) qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED
 *
 *         (c) a string containing the name of an explicit Transition to use
 *
 *         (d) an object where each property name is the Friendly Name of an
 *             object (meaning that this rule applies if both the event and
 *             the event's target object's Friendly Name match), and its
 *             property value is one of (a), (b) or (c), above.
 *
 *       This object is saved in the events property of the state object.
 *
 *     Additional properties may be provided in stateInfo.  They will not be
 *     used by the finite state machine, but will be available via
 *     this.getUserData("<propertyName>") during the state's onentry and
 *     onexit functions.
 */
qx.OO.defineClass("qx.util.fsm.State", qx.core.Object,
function(stateName, stateInfo)
{
  // Call our superclass' constructor
  qx.core.Object.call(this, true);

  // Save the state name
  this.setName(stateName);

  // Ensure they passed in an object
  if (typeof(stateInfo) != "object")
  {
    throw new Error("State info must be an object");
  }

  // Save data from the stateInfo object
  for (var field in stateInfo)
  {
    // If we find one of our properties, call its setter.
    switch(field)
    {
    case "onentry":
      this.setOnentry(stateInfo[field]);
      break;

    case "onexit":
      this.setOnexit(stateInfo[field]);
      break;

    case "autoActionsBeforeOnentry":
      this.setAutoActionsBeforeOnentry(stateInfo[field]);
      break;

    case "autoActionsAfterOnentry":
      this.setAutoActionsAfterOnentry(stateInfo[field]);
      break;

    case "autoActionsBeforeOnexit":
      this.setAutoActionsBeforeOnentry(stateInfo[field]);
      break;

    case "autoActionsBeforeOnexit":
      this.setAutoActionsBeforeOnentry(stateInfo[field]);
      break;

    case "events":
      this.setEvents(stateInfo[field]);
      break;

    default:
      // Anything else is user-provided data for their own use.  Save it.
      this.setUserData(field, stateInfo[field]);

      // Log it in case it was a typo and they intended a built-in field
      this.debug("State " + stateName + ": " +
                 "Adding user-provided field to state: " + field);

      break;
    }
  }


  // Check for required but missing properties
  if (! this.getEvents())
  {
    throw new Error("The events object must be provided in new state info");
  }


  // Initialize the transition list
  this.transitions = { };
});




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/**
 * The name of this state.  This name may be used as a Transition's nextState
 * value, or an explicit next state in the 'events' handling list in a State.
 */
qx.OO.addProperty(
  {
    name         : "name",
    type         : "string"
  });

/**
 * The onentry function for this state.  This is documented in the
 * constructor, and is typically provided through the constructor's stateInfo
 * object, but it is also possible (but highly NOT recommended) to change this
 * dynamically.
 */
qx.OO.addProperty(
  {
    name         : "onentry",
    defaultValue : function(fsm, event) { }
  });

/**
 * The onexit function for this state.  This is documented in the constructor,
 * and is typically provided through the constructor's stateInfo object, but
 * it is also possible (but highly NOT recommended) to change this
 * dynamically.
 */
qx.OO.addProperty(
  {
    name         : "onexit",
    defaultValue : function(fsm, event) { }
  });

/**
 * Automatic actions to take prior to calling the state's onentry function.
 *
 * The value passed to setAutoActionsBeforeOnentry() should like something
 * akin to:
 *
 *     "autoActionsBeforeOnentry" :
 *     {
 *       // The name of a function.  This would become "setEnabled("
 *       "enabled" :
 *       [
 *         {
 *           // The parameter value, thus "setEnabled(true);"
 *           "parameters" : [ true ],
 *
 *           // The function would be called on each object:
 *           //  this.getObject("obj1").setEnabled(true);
 *           //  this.getObject("obj2").setEnabled(true);
 *           "objects" : [ "obj1", "obj2" ]
 *
 *           // And similarly for each object in each specified group.
 *           "groups"  : [ "group1", "group2" ],
 *         }
 *       ];
 *     };
 */
qx.OO.addProperty(
  {
    name         : "autoActionsBeforeOnentry",
    defaultValue : function(fsm, event) { }
  });

/**
 * Automatic actions to take after return from the state's onentry function.
 *
 * The value passed to setAutoActionsAfterOnentry() should like something akin
 * to:
 *
 *     "autoActionsAfterOnentry" :
 *     {
 *       // The name of a function.  This would become "setEnabled("
 *       "enabled" :
 *       [
 *         {
 *           // The parameter value, thus "setEnabled(true);"
 *           "parameters" : [ true ],
 *
 *           // The function would be called on each object:
 *           //  this.getObject("obj1").setEnabled(true);
 *           //  this.getObject("obj2").setEnabled(true);
 *           "objects" : [ "obj1", "obj2" ]
 *
 *           // And similarly for each object in each specified group.
 *           "groups"  : [ "group1", "group2" ],
 *         }
 *       ];
 *     };
 */
qx.OO.addProperty(
  {
    name         : "autoActionsAfterOnentry",
    defaultValue : function(fsm, event) { }
  });

/**
 * Automatic actions to take prior to calling the state's onexit function.
 *
 * The value passed to setAutoActionsBeforeOnexit() should like something akin
 * to:
 *
 *     "autoActionsBeforeOnexit" :
 *     {
 *       // The name of a function.  This would become "setEnabled("
 *       "enabled" :
 *       [
 *         {
 *           // The parameter value, thus "setEnabled(true);"
 *           "parameters" : [ true ],
 *
 *           // The function would be called on each object:
 *           //  this.getObject("obj1").setEnabled(true);
 *           //  this.getObject("obj2").setEnabled(true);
 *           "objects" : [ "obj1", "obj2" ]
 *
 *           // And similarly for each object in each specified group.
 *           "groups"  : [ "group1", "group2" ],
 *         }
 *       ];
 *     };
 */
qx.OO.addProperty(
  {
    name         : "autoActionsBeforeOnexit",
    defaultValue : function(fsm, event) { }
  });


/**
 * Automatic actions to take after returning from the state's onexit function.
 *
 * The value passed to setAutoActionsAfterOnexit() should like something akin
 * to:
 *
 *     "autoActionsBeforeOnexit" :
 *     {
 *       // The name of a function.  This would become "setEnabled("
 *       "enabled" :
 *       [
 *         {
 *           // The parameter value, thus "setEnabled(true);"
 *           "parameters" : [ true ],
 *
 *           // The function would be called on each object:
 *           //  this.getObject("obj1").setEnabled(true);
 *           //  this.getObject("obj2").setEnabled(true);
 *           "objects" : [ "obj1", "obj2" ]
 *
 *           // And similarly for each object in each specified group.
 *           "groups"  : [ "group1", "group2" ],
 *         }
 *       ];
 *     };
 */
qx.OO.addProperty(
  {
    name         : "autoActionsAfterOnexit",
    defaultValue : function(fsm, event) { }
  });


/**
 * The object representing handled and blocked events for this state.  This is
 * documented in the constructor, and is typically provided through the
 * constructor's stateInfo object, but it is also possible (but highly NOT
 * recommended) to change this dynamically.
 */
qx.OO.addProperty(
  {
    name         : "events"
  });



/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._checkName = function(propValue, propData)
{
  // Ensure that we got a valid state name
  if (typeof(propValue) != "string" || propValue.length < 1)
  {
    throw new Error("Invalid state name");
  }

  return propValue;
};

qx.Proto._checkOnentry = function(propValue, propData)
{
  // Validate the onentry function
  switch(typeof(propValue))
  {
  case "undefined":
    // None provided.  Convert it to a null function
    return function(fsm, event) {};

  case "function":
    // We're cool.  No changes required
    return propValue;

  default:
    throw new Error("Invalid onentry type: " + typeof(propValue));
    return null;
  }
};

qx.Proto._checkOnexit = function(propValue, propData)
{
  // Validate the onexit function
  switch(typeof(propValue))
  {
  case "undefined":
    // None provided.  Convert it to a null function
    return function(fsm, event) {};

  case "function":
    // We're cool.  No changes required
    return propValue;

  default:
    throw new Error("Invalid onexit type: " + typeof(propValue));
    return null;
  }
};

qx.Proto._checkEvents = function(propValue, propData)
{
  // Validate that events is an object
  if (typeof(propValue) != "object")
  {
    throw new Error("events must be an object");
  }

  // Confirm that each property is a valid value
  // The property value should be one of:
  //
  // (a) qx.util.fsm.FiniteStateMachine.EventHandling.PREDICATE
  //
  // (b) qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED
  //
  // (c) a string containing the name of an explicit Transition to use
  //
  // (d) an object where each property name is the Friendly Name of an
  //     object (meaning that this rule applies if both the event and
  //     the event's target object's Friendly Name match), and its
  //     property value is one of (a), (b) or (c), above.
  for (var e in propValue)
  {
    var action = propValue[e];
    if (typeof(action) == "number" &&
        action != qx.util.fsm.FiniteStateMachine.EventHandling.PREDICATE &&
        action != qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED)
    {
      throw new Error("Invalid numeric value in events object: " +
                      e + ": " + action);
    }
    else if (typeof(action) == "object")
    {
      for (action_e in action)
      {
        if (typeof(action[action_e]) == "number" &&
            action != qx.util.fsm.FiniteStateMachine.EventHandling.PREDICATE &&
            action != qx.util.fsm.FiniteStateMachine.EventHandling.BLOCKED)
        {
          throw new Error("Invalid numeric value in events object " +
                          "(" + e + "): " +
                          action_e + ": " + action[action_e]);
        }
        else if (typeof(action[action_e]) != "string")
        {
          throw new Error("Invalid value in events object " +
                          "(" + e + "): " +
                          action_e + ": " + action[action_e]);
        }
      }
    }
    else if (typeof(action) != "string")
    {
      throw new Error("Invalid value in events object: " +
                      e + ": " + propValue[e]);
    }
  }

  // We're cool.  No changes required.
  return propValue;
};

qx.Proto._checkAutoActionsBeforeOnentry = function(propValue, propData)
{
  return qx.util.fsm.FiniteStateMachine._commonCheckAutoActions(
    "autoActionsBeforeOnentry",
    propValue,
    propData);
};

qx.Proto._checkAutoActionsAfterOnentry = function(propValue, propData)
{
  return qx.util.fsm.FiniteStateMachine._commonCheckAutoActions(
    "autoActionsAfterOnentry",
    propValue,
    propData);
};

qx.Proto._checkAutoActionsBeforeOnexit = function(propValue, propData)
{
  return qx.util.fsm.FiniteStateMachine._commonCheckAutoActions(
    "autoActionsBeforeOnexit",
    propValue,
    propData);
};

qx.Proto._checkAutoActionsAfterOnexit = function(propValue, propData)
{
  return qx.util.fsm.FiniteStateMachine._commonCheckAutoActions(
    "autoActionsAfterOnexit",
    propValue,
    propData);
};


/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

/**
 * Add a transition to a state
 *
 * @param trans {qx.util.fsm.Transition}
 *   An object of class qx.util.fsm.Transition representing a
 *   transition which is to be a part of this state.
 */
qx.Proto.addTransition = function(trans)
{
  // Ensure that we got valid transition info
  if (! trans instanceof qx.util.fsm.Transition)
  {
    throw new Error("Invalid transition: not an instance of " +
                    "qx.util.fsm.Transition");
  }

  // Add the new transition object to the state
  this.transitions[trans.getName()] = trans;
};




/*
---------------------------------------------------------------------------
  EVENT LISTENERS
---------------------------------------------------------------------------
*/



/*
---------------------------------------------------------------------------
  CLASS CONSTANTS
---------------------------------------------------------------------------
*/



/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  return qx.core.Object.prototype.dispose.call(this);
}
