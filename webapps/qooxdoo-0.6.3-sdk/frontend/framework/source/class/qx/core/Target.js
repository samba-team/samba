/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(core)

************************************************************************ */

/**
 * This is the main constructor for all objects that need to be connected to qx.event.type.Event objects.
 *
 * In objects created with this constructor, you find functions to addEventListener or
 * removeEventListener to or from the created object. Each event to connect to has a type in
 * form of an identification string. This type could be the name of a regular dom event like "click" or
 * something self-defined like "ready".
 *
 * @param vAutoDispose {boolean ? true} wether the object should be disposed automatically by qooxdoo
 */
qx.OO.defineClass("qx.core.Target", qx.core.Object,
function(vAutoDispose) {
  qx.core.Object.call(this, vAutoDispose);
});

/**
 * @private
 */
qx.Class.EVENTPREFIX = "evt";




/*
---------------------------------------------------------------------------
  EVENT CONNECTION
---------------------------------------------------------------------------
*/

/**
 * Add event listener to an object.
 *
 * @param vType {string} name of the event type
 * @param vFunction {Function} event callback function
 * @param vObject {object ? window} reference to the 'this' variable inside the callback
 */
qx.Proto.addEventListener = function(vType, vFunction, vObject)
{
  if(this._disposed) {
    return;
  }

  if(typeof vFunction !== "function") {
    throw new Error("qx.core.Target: addEventListener(" + vType + "): '" + vFunction + "' is not a function!");
  }

  // If this is the first event of given type, we need to create a subobject
  // that contains all the actions that will be assigned to this type
  if (typeof this._listeners === "undefined")
  {
    this._listeners = {};
    this._listeners[vType] = {};
  }
  else if(typeof this._listeners[vType] === "undefined")
  {
    this._listeners[vType] = {};
  }

  // Create a special vKey string to allow identification of each bound action
  var vKey = qx.core.Target.EVENTPREFIX + qx.core.Object.toHashCode(vFunction) + (vObject ? "_" + qx.core.Object.toHashCode(vObject) : "");

  // Finally set up the listeners object
  this._listeners[vType][vKey] =
  {
    handler : vFunction,
    object : vObject
  }
}


/**
 * Remove event listener from object
 *
 * @param vType {string} name of the event type
 * @param vFunction {Function} event callback function
 * @param vObject {object ? window} reference to the 'this' variable inside the callback
 */
qx.Proto.removeEventListener = function(vType, vFunction, vObject)
{
  if(this._disposed) {
    return;
  }

  var vListeners = this._listeners;
  if (!vListeners || typeof vListeners[vType] === "undefined") {
    return;
  }

  if(typeof vFunction !== "function") {
    throw new Error("qx.core.Target: removeEventListener(" + vType + "): '" + vFunction + "' is not a function!");
  }

  // Create a special vKey string to allow identification of each bound action
  var vKey = qx.core.Target.EVENTPREFIX + qx.core.Object.toHashCode(vFunction) + (vObject ? "_" + qx.core.Object.toHashCode(vObject) : "");

  // Delete object entry for this action
  delete this._listeners[vType][vKey];
}



/*
---------------------------------------------------------------------------
  EVENT CONNECTION UTILITIES
---------------------------------------------------------------------------
*/

/**
 * Check if there are one or more listeners for an event type.
 *
 * @param vType {string} name of the event type
 */
qx.Proto.hasEventListeners = function(vType) {
  return this._listeners && typeof this._listeners[vType] !== "undefined" && !qx.lang.Object.isEmpty(this._listeners[vType]);
}


/**
 * Checks if the event is registered. If so it creates an event object and dispatches it.
 *
 * @param vType {string} name of the event type
 */
qx.Proto.createDispatchEvent = function(vType)
{
  if (this.hasEventListeners(vType)) {
    this.dispatchEvent(new qx.event.type.Event(vType), true);
  }
}


/**
 * Checks if the event is registered. If so it creates an event object and dispatches it.
 *
 * @param vType {string} name of the event type
 * @param vData {Object} user defined data attached to the event object
 */
qx.Proto.createDispatchDataEvent = function(vType, vData)
{
  if (this.hasEventListeners(vType)) {
    this.dispatchEvent(new qx.event.type.DataEvent(vType, vData), true);
  }
}



/*
---------------------------------------------------------------------------
  EVENT DISPATCH
---------------------------------------------------------------------------
*/

/**
 * Dispatch an event
 *
 * @param vEvent {qx.event.type.Event} event to dispatch
 * @param vEnableDispose {boolean} wether the event object should be disposed after all event handlers run.
 * @return {boolean} wether the event default was prevented or not. Returns true, when the event was NOT prevented.
 */
qx.Proto.dispatchEvent = function(vEvent, vEnableDispose)
{
  // Ignore event if eventTarget is disposed
  if(this.getDisposed() && this.getEnabled()) {
    return;
  }

  if (vEvent.getTarget() == null) {
    vEvent.setTarget(this);
  }

  if (vEvent.getCurrentTarget() == null) {
    vEvent.setCurrentTarget(this);
  }

  // Dispatch Event
  this._dispatchEvent(vEvent, vEnableDispose);

  // Read default prevented
  var defaultPrevented = vEvent._defaultPrevented;

  // enable dispose for event?
  vEnableDispose && vEvent.dispose();

  return !defaultPrevented;
}


/**
 * Internal event dispatch method
 *
 * @param vEvent {qx.event.type.Event} event to dispatch
 */
qx.Proto._dispatchEvent = function(vEvent)
{
  var vListeners = this._listeners;
  if (vListeners)
  {
    // Setup current target
    vEvent.setCurrentTarget(this);

    // Shortcut for listener data
    var vTypeListeners = vListeners[vEvent.getType()];

    if(vTypeListeners)
    {
      var vFunction, vObject;

      // Handle all events for the specified type
      for (var vHashCode in vTypeListeners)
      {
        // Shortcuts for handler and object
        vFunction = vTypeListeners[vHashCode].handler;
        vObject = vTypeListeners[vHashCode].object;

        // Call object function
        try
        {
          if(typeof vFunction === "function") {
            vFunction.call(qx.util.Validation.isValid(vObject) ? vObject : this, vEvent);
          }
        }
        catch(ex)
        {
          this.error("Could not dispatch event of type \"" + vEvent.getType() + "\"", ex);
        }
      }
    }
  }

  // Bubble event to parents
  // TODO: Move this to Parent or Widget?
  if(vEvent.getBubbles() && !vEvent.getPropagationStopped() && this.getParent)
  {
    var vParent = this.getParent();
    if (vParent && !vParent.getDisposed() && vParent.getEnabled()) {
      vParent._dispatchEvent(vEvent);
    }
  }
}




/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

/**
 * Destructor.
 */
qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  if (typeof this._listeners === "object")
  {
    for (var vType in this._listeners)
    {
      var listener = this._listeners[vType];
      for (var vKey in listener)
      {
        listener[vKey] = null;
      }

      this._listeners[vType] = null;
    }
  }

  this._listeners = null;

  return qx.core.Object.prototype.dispose.call(this);
}
