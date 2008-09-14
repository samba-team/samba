/*
 *	@file 	event.js
 *	@brief 	Event class
 *	@copy 	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 *
 *	Usage:
 *		listener = new System.Listener();
 *		listener.onClick = function() {
 *			// Any code here 
 *		}
 *		eventTarget.addListener(eventName, listener);
 *	or
 *		listener = new System.Listener(obj, method);
 *		eventTarget.addListener(eventName, listener);
 *
 *	To fire events:
 *		eventTarget.fire(eventName, new System.Event("My Event"));
 */

/******************************************************************************/
/*
 *	Base event class
 */
class System.Event 
{
	var		type;							// keyboard
	var 	timeStamp;
	var		arg;

	/* MOB -- constructor should take a type */
	function Event(arg)
	{
		timeStamp = time();
		type = "default";
		this.arg = arg;
	}
}

/* MOB -- should not be needed */
Event = System.Event;

class System.Listener
{
	var		obj;
	var		method;

	function Listener(obj, method)
	{
		if (arguments.length >= 1) {
			this.obj = obj;
		} else {
			this.obj = this;
		}
		if (arguments.length == 2) {
			this.method = method;
		} else {
			this.method = "onEvent";
		}
	}
}
/* MOB -- should not be needed */
Listener = System.Listener;


/*
 *	The Event target class
 */
class System.EventTarget
{
	//	Private
	var	events;								/* Hash of a event names */

	function EventTarget()
	{
		events = new Object();
	}

	//	Public
	function addListener(eventName, listener) 
	{
		var listeners = events[eventName];
		if (listeners == undefined) {
			listeners = events[eventName] = new Array();
		}
		if (arguments.length == 2) {
			var method = eventName;
		}
		/* MOB OPT */
		for (var i = 0; i < listeners.length; i++) {
			var l = listeners[i];
			if (l == listener) {
				return;
			}
		}
		listeners[listeners.length] = listener;
	}

	function removeListener(eventName, listener)
	{
		var listeners = events[eventName];

		if (listeners == undefined) {
			return;
		}

		for (var i = 0; i < listeners.length; i++) {
			var l = listeners[i];
			if (l == listener) {
				// MOB -- want listeners.splice here
				// listeners.splice(i, 1);
				for (var j = i; j < (listeners.length - 1); j++) {
					listeners[j] = listeners[j + 1];
				}
				delete listeners[listeners.length - 1];
				i = listeners.length;
			}
		}
	}

	function fire(eventName, event) 
	{
		var listeners = events[eventName];
	
		if (listeners == undefined) {
			// println("Event.fire(): unknown eventName " + eventName);
			return;
		}

		for (var i = listeners.length - 1; i >= 0; i--) {
			var listener = listeners[i];
			var method = listener.obj[listener.method];
			if (method == undefined) {
				throw new EvalError("Undefined method: " + listener.method);
			}
			listener.obj[listener.method](listener, event);
		}
	}
}

/* MOB -- should not be needed */
EventTarget = System.EventTarget;
