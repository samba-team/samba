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

#module(ui_core)
#require(qx.event.type.KeyEvent)
#require(qx.event.handler.KeyEventHandler)
#optional(qx.event.handler.DragAndDropHandler)
#optional(qx.manager.object.MenuManager)
#optional(qx.event.handler.FocusHandler)
#optional(qx.manager.object.PopupManager)
#optional(qx.manager.object.ToolTipManager)

************************************************************************ */

/*!
  This manager registers and manage all incoming key and mouse events.
*/
qx.OO.defineClass("qx.event.handler.EventHandler", qx.core.Target,
function()
{
  qx.core.Target.call(this);

  // Object Wrapper to Events (Needed for DOM-Events)
  var o = this;

  // User Events
  this.__onmouseevent = function(e) { return o._onmouseevent(e); };
  this.__ondragevent = function(e) { return o._ondragevent(e); };
  this.__onselectevent = function(e) { return o._onselectevent(e); };

  // Window Events
  this.__onwindowblur = function(e) { return o._onwindowblur(e); };
  this.__onwindowfocus = function(e) { return o._onwindowfocus(e); };
  this.__onwindowresize = function(e) { return o._onwindowresize(e); };

  // Init Command Interface
  this._commands = {};
});






qx.OO.addProperty({ name : "allowClientContextMenu", type : "boolean", defaultValue : false });
qx.OO.addProperty({ name : "allowClientSelectAll", type : "boolean", defaultValue : false });

qx.OO.addProperty({ name : "captureWidget", type : "object", instance : "qx.ui.core.Widget", allowNull : true });
qx.OO.addProperty({ name : "focusRoot", type : "object", instance : "qx.ui.core.Parent", allowNull : true });






qx.Class.mouseEventTypes = [ "mouseover", "mousemove", "mouseout", "mousedown", "mouseup", "click", "dblclick", "contextmenu", qx.sys.Client.getInstance().isMshtml() ? "mousewheel" : "DOMMouseScroll" ];
qx.Class.keyEventTypes = [ "keydown", "keypress", "keyup" ];

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Class.dragEventTypes = [ "dragdrop", "dragover", "dragenter", "dragexit", "draggesture" ];
}
else if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Class.dragEventTypes = [ "dragend", "dragover", "dragstart", "drag", "dragenter", "dragleave" ];
}
else
{
  qx.Class.dragEventTypes = [ "dragstart", "dragdrop", "dragover", "drag", "dragleave", "dragenter", "dragexit", "draggesture" ];
}










/*
---------------------------------------------------------------------------
  STATE FLAGS
---------------------------------------------------------------------------
*/

qx.Proto._lastMouseEventType = null;
qx.Proto._lastMouseDown = false;
qx.Proto._lastMouseEventDate = 0;






/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyCaptureWidget = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.setCapture(false);
  }

  if (propValue) {
    propValue.setCapture(true);
  }

  return true;
}

qx.Proto._modifyFocusRoot = function(propValue, propOldValue, propData)
{
  // this.debug("FocusRoot: " + propValue + "(from:" + propOldValue + ")");

  if (propOldValue) {
    propOldValue.setFocusedChild(null);
  }

  if (propValue)
  {
    if (propValue.getFocusedChild() == null) {
      propValue.setFocusedChild(propValue);
    }
  }

  return true;
}






/*
---------------------------------------------------------------------------
  COMMAND INTERFACE
---------------------------------------------------------------------------
*/

qx.Proto.addCommand = function(vCommand) {
  this._commands[vCommand.toHashCode()] = vCommand;
}

qx.Proto.removeCommand = function(vCommand) {
  delete this._commands[vCommand.toHashCode()];
}

qx.Proto._checkKeyEventMatch = function(e)
{
  var vCommand;

  for (var vHash in this._commands)
  {
    vCommand = this._commands[vHash];

    if (vCommand.getEnabled() && vCommand._matchesKeyEvent(e))
    {
      // allow the user to stop the event
      // through the execute event.
      if (!vCommand.execute()) {
        e.preventDefault();
      }

      break;
    }
  }
}






/*
---------------------------------------------------------------------------
  EVENT-MAPPING
---------------------------------------------------------------------------
*/

qx.Proto.attachEvents = function()
{
  // Register dom events
  this.attachEventTypes(qx.event.handler.EventHandler.mouseEventTypes, this.__onmouseevent);
  this.attachEventTypes(qx.event.handler.EventHandler.dragEventTypes, this.__ondragevent);

  // Unregister separate handler events
  qx.event.handler.KeyEventHandler.getInstance()._attachEvents();

  // Register window events
  qx.dom.EventRegistration.addEventListener(window, "blur", this.__onwindowblur);
  qx.dom.EventRegistration.addEventListener(window, "focus", this.__onwindowfocus);
  qx.dom.EventRegistration.addEventListener(window, "resize", this.__onwindowresize);

  // Register selection events
  document.body.onselect = document.onselectstart = document.onselectionchange = this.__onselectevent;
}

qx.Proto.detachEvents = function()
{
  // Unregister dom events
  this.detachEventTypes(qx.event.handler.EventHandler.mouseEventTypes, this.__onmouseevent);
  this.detachEventTypes(qx.event.handler.EventHandler.dragEventTypes, this.__ondragevent);

  // Unregister separate handler events
  qx.event.handler.KeyEventHandler.getInstance()._detachEvents();

  // Unregister window events
  qx.dom.EventRegistration.removeEventListener(window, "blur", this.__onwindowblur);
  qx.dom.EventRegistration.removeEventListener(window, "focus", this.__onwindowfocus);
  qx.dom.EventRegistration.removeEventListener(window, "resize", this.__onwindowresize);

  // Unregister selection events
  document.body.onselect = document.onselectstart = document.onselectionchange = null;
}







/*
---------------------------------------------------------------------------
  EVENT-MAPPING HELPER
---------------------------------------------------------------------------
*/

qx.Proto.attachEventTypes = function(vEventTypes, vFunctionPointer)
{
  try
  {
    // Gecko is a bit buggy to handle key events on document if not previously focused
    // I think they will fix this sometimes, and we should add a version check here.
    // Internet Explorer has problems to use 'window', so there we use the 'body' element
    // as previously.
    var el = qx.sys.Client.getInstance().isGecko() ? window : document.body;

    for (var i=0, l=vEventTypes.length; i<l; i++) {
      qx.dom.EventRegistration.addEventListener(el, vEventTypes[i], vFunctionPointer);
    }
  }
  catch(ex)
  {
    throw new Error("qx.event.handler.EventHandler: Failed to attach window event types: " + vEventTypes + ": " + ex);
  }
}

qx.Proto.detachEventTypes = function(vEventTypes, vFunctionPointer)
{
  try
  {
    var el = qx.sys.Client.getInstance().isGecko() ? window : document.body;

    for (var i=0, l=vEventTypes.length; i<l; i++) {
      qx.dom.EventRegistration.removeEventListener(el, vEventTypes[i], vFunctionPointer);
    }
  }
  catch(ex)
  {
    throw new Error("qx.event.handler.EventHandler: Failed to detach window event types: " + vEventTypes + ": " + ex);
  }
}






/*
---------------------------------------------------------------------------
  HELPER METHODS
---------------------------------------------------------------------------
*/

// BUG: http://xscroll.mozdev.org/
// If your Mozilla was built with an option `--enable-default-toolkit=gtk2',
// it can not return the correct event target for DOMMouseScroll.

qx.Class.getOriginalTargetObject = function(vNode)
{
  // Events on the HTML element, when using absolute locations which
  // are outside the HTML element. Opera does not seem to fire events
  // on the HTML element.
  if (vNode == document.documentElement) {
    vNode = document.body;
  }

  // Walk up the tree and search for an qx.ui.core.Widget
  while(vNode != null && vNode.qx_Widget == null)
  {
    try {
      vNode = vNode.parentNode;
    }
    catch(vDomEvent)
    {
      vNode = null;
    }
  }

  return vNode ? vNode.qx_Widget : null;
}

if (qx.sys.Client.getInstance().isWebkit())
{
  /**
   * extract the target node from a DOM event
   * http://www.quirksmode.org/js/events_properties.html
   *
   * @param vDomEvent {Event}
   * @return {Element} the target node
   */
  qx.Class.getDomTarget = function(vDomEvent)
  {
    var vNode = vDomEvent.target || vDomEvent.srcElement;

    // Safari takes text nodes as targets for events
    if (vNode && (vNode.nodeType == qx.dom.Node.TEXT)) {
      vNode = vNode.parentNode;
    }

    return vNode;
  };
}
else if (qx.sys.Client.getInstance().isMshtml())
{
  /**
   * extract the target node from a DOM event
   * http://www.quirksmode.org/js/events_properties.html
   *
   * @param vDomEvent {Event}
   * @return {Element} the target node
   */
  qx.Class.getDomTarget = function(vDomEvent) {
    return vDomEvent.target || vDomEvent.srcElement;
  };
}
else
{
  /**
   * extract the target node from a DOM event
   * http://www.quirksmode.org/js/events_properties.html
   *
   * @param vDomEvent {Event}
   * @return {Element} the target node
   */
  qx.Class.getDomTarget = function(vDomEvent) {
    return vDomEvent.target;
  };
}


qx.Class.getOriginalTargetObjectFromEvent = function(vDomEvent, vWindow)
{
  var vNode = qx.event.handler.EventHandler.getDomTarget(vDomEvent);

  // Especially to fix key events.
  // 'vWindow' is the window reference then
  if (vWindow)
  {
    var vDocument = vWindow.document;

    if (vNode == vWindow || vNode == vDocument || vNode == vDocument.documentElement || vNode == vDocument.body) {
      return vDocument.body.qx_Widget;
    }
  }

  return qx.event.handler.EventHandler.getOriginalTargetObject(vNode);
}

qx.Class.getRelatedOriginalTargetObjectFromEvent = function(vDomEvent) {
  return qx.event.handler.EventHandler.getOriginalTargetObject(vDomEvent.relatedTarget || (vDomEvent.type == "mouseover" ? vDomEvent.fromElement : vDomEvent.toElement));
}







qx.Class.getTargetObject = function(vNode, vObject)
{
  if (!vObject)
  {
    var vObject = qx.event.handler.EventHandler.getOriginalTargetObject(vNode);

    if (!vObject) {
      return null;
    }
  }

  // Search parent tree
  while(vObject)
  {
    // Break if current object is disabled -
    // event should be ignored then.
    if (!vObject.getEnabled()) {
      return null;
    }

    // If object is anonymous, search for
    // first parent which is not anonymous
    // and not disabled
    if (!vObject.getAnonymous()) {
      break;
    }

    vObject = vObject.getParent();
  }

  return vObject;
};


qx.Class.getTargetObjectFromEvent = function(vDomEvent) {
  return qx.event.handler.EventHandler.getTargetObject(qx.event.handler.EventHandler.getDomTarget(vDomEvent));
};


qx.Class.getRelatedTargetObjectFromEvent = function(vDomEvent) {
  var target = vDomEvent.relatedTarget;
  if (!target) {
    if (vDomEvent.type == "mouseover") {
      target = vDomEvent.fromElement
    } else {
      target = vDomEvent.toElement
    }
  }
  return qx.event.handler.EventHandler.getTargetObject(target);
};


/**
 * stops further propagation of the event
 *
 * @param vDomEvent (Element) DOM event object
 */
qx.Class.stopDomEvent = function(vDomEvent) {};
if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Class.stopDomEvent = function(vDomEvent) {
    vDomEvent.returnValue = false;
  }
}
else
{
  qx.Class.stopDomEvent = function(vDomEvent)
  {
    vDomEvent.preventDefault();
    vDomEvent.returnValue = false;
  }
};







/*
---------------------------------------------------------------------------
  KEY EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onkeyevent_post = function(vDomEvent, vType, vKeyCode, vCharCode, vKeyIdentifier)
{
  var vDomTarget = qx.event.handler.EventHandler.getDomTarget(vDomEvent);


  // Find current active qooxdoo object
  var vFocusRoot = this.getFocusRoot();
  var vTarget = this.getCaptureWidget() || (vFocusRoot == null ? null : vFocusRoot.getActiveChild());

  if (vTarget == null || !vTarget.getEnabled()) {
    return false;
  }

  var vDomEventTarget = vTarget.getElement();




  // Hide Menus
  switch(vKeyIdentifier)
  {
    case "Escape":
    case "Tab":
      if (qx.OO.isAvailable("qx.manager.object.MenuManager")) {
        qx.manager.object.MenuManager.getInstance().update(vTarget, vType);
      }

      break;
  }




  // TODO: Move this to KeyEvent?

  // Prohibit CTRL+A
  if (!this.getAllowClientSelectAll())
  {
    if (vDomEvent.ctrlKey && vKeyIdentifier == "A")
    {
      switch(vDomTarget.tagName.toLowerCase())
      {
        case "input":
        case "textarea":
        case "iframe":
          break;

        default:
          qx.event.handler.EventHandler.stopDomEvent(vDomEvent);
      }
    }
  }



  // Create Event Object
  var vKeyEventObject = new qx.event.type.KeyEvent(vType, vDomEvent, vDomTarget, vTarget, null, vKeyCode, vCharCode, vKeyIdentifier);

  // Check for commands
  if (vDomEvent.type == "keydown") {
    this._checkKeyEventMatch(vKeyEventObject);
  }

  // Starting Objects Internal Event Dispatcher
  // This handles the real event action
  vTarget.dispatchEvent(vKeyEventObject);

  // Send event to qx.event.handler.DragAndDropHandler
  if (qx.OO.isAvailable("qx.event.handler.DragAndDropHandler")) {
    qx.event.handler.DragAndDropHandler.getInstance().handleKeyEvent(vKeyEventObject);
  }

  // Cleanup Event Object
  vKeyEventObject.dispose();

  // Flush Queues
  qx.ui.core.Widget.flushGlobalQueues();
}






/*
---------------------------------------------------------------------------
  MOUSE EVENTS
---------------------------------------------------------------------------
*/

/*!
  This one handle all mouse events

  When a user double clicks on a qx.ui.core.Widget the
  order of the mouse events is the following:

  1. mousedown
  2. mouseup
  3. click
  4. mousedown
  5. mouseup
  6. click
  7. dblclick
*/

if(qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._onmouseevent = function(vDomEvent)
  {
    qx.core.Init.getInstance().getComponent().preload();

    if(!vDomEvent) {
      vDomEvent = window.event;
    }

    var vDomTarget = qx.event.handler.EventHandler.getDomTarget(vDomEvent);
    var vType = vDomEvent.type;

    if(vType == "mousemove")
    {
      if (this._mouseIsDown && vDomEvent.button == 0)
      {
        this._onmouseevent_post(vDomEvent, "mouseup");
        this._mouseIsDown = false;
      }
    }
    else
    {
      if(vType == "mousedown")
      {
        this._mouseIsDown = true;
      }
      else if(vType == "mouseup")
      {
        this._mouseIsDown = false;
      }

      // Fix MSHTML Mouseup, should be after a normal click or contextmenu event, like Mozilla does this
      if(vType == "mouseup" && !this._lastMouseDown && ((new Date).valueOf() - this._lastMouseEventDate) < 250)
      {
        this._onmouseevent_post(vDomEvent, "mousedown");
      }
      // Fix MSHTML Doubleclick, should be after a normal click event, like Mozilla does this
      else if(vType == "dblclick" && this._lastMouseEventType == "mouseup" && ((new Date).valueOf() - this._lastMouseEventDate) < 250)
      {
        this._onmouseevent_post(vDomEvent, "click");
      }

      switch(vType)
      {
        case "mousedown":
        case "mouseup":
        case "click":
        case "dblclick":
        case "contextmenu":
          this._lastMouseEventType = vType;
          this._lastMouseEventDate = (new Date).valueOf();
          this._lastMouseDown = vType == "mousedown";
      }
    }

    this._onmouseevent_post(vDomEvent, vType, vDomTarget);
  }
}
else
{
  qx.Proto._onmouseevent = function(vDomEvent)
  {
    qx.core.Init.getInstance().getComponent().preload();

    var vDomTarget = qx.event.handler.EventHandler.getDomTarget(vDomEvent);
    var vType = vDomEvent.type;

    switch(vType)
    {
      case "DOMMouseScroll":
        // normalize mousewheel event
        vType = "mousewheel";
        break;

      case "click":
      case "dblclick":
        // ignore click or dblclick events with other then the left mouse button
        if (vDomEvent.which !== 1) {
          return;
        }
    }

    this._onmouseevent_post(vDomEvent, vType, vDomTarget);
  }
}

/*!
Fixes browser quirks with 'click' detection

Firefox 1.5.0.6: The DOM-targets are different. The click event only fires, if the target of the
  mousedown is the same than with the mouseup. If the content moved away, the click isn't fired.

Internet Explorer 6.0: The DOM-targets are identical and the click fires fine.

Opera 9.01: The DOM-targets are different, but the click fires fine. Fires click successfull,
  even if the content under the cursor was moved away.
*/
if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._onmouseevent_click_fix = function(vDomTarget, vType, vDispatchTarget)
  {
    var vReturn = false;

    switch(vType)
    {
      case "mousedown":
        this._lastMouseDownDomTarget = vDomTarget;
        this._lastMouseDownDispatchTarget = vDispatchTarget;
        break;

      case "mouseup":
        // Add additional click event if the dispatch target is the same, but the dom target is different
        if (this._lastMouseDownDispatchTarget === vDispatchTarget && vDomTarget !== this._lastMouseDownDomTarget)
        {
          vReturn = true;
        }
        else
        {
          this._lastMouseDownDomTarget = null;
          this._lastMouseDownDispatchTarget = null;
        }
    }

    return vReturn;
  };
}
else
{
  qx.Proto._onmouseevent_click_fix = function(vDomTarget, vDispatchTarget) {
    return false;
  }
};

/*!
  This is the crossbrowser post handler for all mouse events.
*/
qx.Proto._onmouseevent_post = function(vDomEvent, vType, vDomTarget)
{
  try
  {
    var vEventObject, vCaptureTarget, vDispatchTarget, vTarget, vOriginalTarget, vRelatedTarget, vFixClick;







    // Check for capturing, if enabled the target is the captured widget.
    vCaptureTarget = this.getCaptureWidget();

    // Event Target Object
    vOriginalTarget = qx.event.handler.EventHandler.getOriginalTargetObject(vDomTarget);

    // If capturing isn't active search for a valid target object
    if (!vCaptureTarget)
    {
      // Get Target Object
      vDispatchTarget = vTarget = qx.event.handler.EventHandler.getTargetObject(null, vOriginalTarget);
    }
    else
    {
      vDispatchTarget = vCaptureTarget;
      vTarget = qx.event.handler.EventHandler.getTargetObject(null, vOriginalTarget);
    }



    // If there is no target, we have nothing to do
    if (!vTarget) {
      return false;
    }

    // Fix click event
    vFixClick = this._onmouseevent_click_fix(vDomTarget, vType, vDispatchTarget);




    switch(vType)
    {
      case "contextmenu":
        if (!this.getAllowClientContextMenu()) {
          qx.event.handler.EventHandler.stopDomEvent(vDomEvent);
        }

        break;

      case "mousedown":
        qx.event.handler.FocusHandler.mouseFocus = true;

        var vRoot = vTarget.getFocusRoot();

        if (vRoot)
        {
          this.setFocusRoot(vRoot);

          vRoot.setActiveChild(vTarget);

          // Active focus on element (if possible, else search up the parent tree)
          var vFocusTarget = vTarget;
          while (!vFocusTarget.isFocusable() && vFocusTarget != vRoot) {
            vFocusTarget = vFocusTarget.getParent();
          }

          vRoot.setFocusedChild(vFocusTarget);
        }

        break;
    }




    var vDomEventTarget = vTarget.getElement();




    // Find related target object
    switch(vType)
    {
      case "mouseover":
      case "mouseout":
        vRelatedTarget = qx.event.handler.EventHandler.getRelatedTargetObjectFromEvent(vDomEvent);

        // Ignore events where the related target and
        // the real target are equal - from our sight
        if (vRelatedTarget == vTarget) {
          return;
        }
    }



    try
    {

      // Create Mouse Event Object
      vEventObject = new qx.event.type.MouseEvent(vType, vDomEvent, vDomTarget, vTarget, vOriginalTarget, vRelatedTarget);
    }
    catch(ex)
    {
      return this.error("Failed to create mouse event", ex);
    }


    // Store last Event in MouseEvent Constructor
    // Needed for Tooltips, ...
    qx.event.type.MouseEvent._storeEventState(vEventObject);



    try
    {
      // Dispatch Event through target (eventtarget-)object
      var vReturnValue = vDispatchTarget ? vDispatchTarget.dispatchEvent(vEventObject) : true;
    }
    catch(ex)
    {
      return this.error("Failed to dispatch mouse event", ex);
    }





    // Handle Special Post Events
    switch(vType)
    {
      case "mousedown":
        if (qx.OO.isAvailable("qx.manager.object.PopupManager")) {
          qx.manager.object.PopupManager.getInstance().update(vTarget);
        }

        if (qx.OO.isAvailable("qx.manager.object.MenuManager")) {
          qx.manager.object.MenuManager.getInstance().update(vTarget, vType);
        }

        if (qx.OO.isAvailable("qx.manager.object.IframeManager")) {
          qx.manager.object.IframeManager.getInstance().handleMouseDown(vEventObject);
        }

        break;

      case "mouseup":

        // Mouseup event should always hide, independed of target, so don't send a target
        if (qx.OO.isAvailable("qx.manager.object.MenuManager")) {
          qx.manager.object.MenuManager.getInstance().update(vTarget, vType);
        }

        if (qx.OO.isAvailable("qx.manager.object.IframeManager")) {
          qx.manager.object.IframeManager.getInstance().handleMouseUp(vEventObject);
        }

        break;

      case "mouseover":
        if (qx.OO.isAvailable("qx.manager.object.ToolTipManager")) {
          qx.manager.object.ToolTipManager.getInstance().handleMouseOver(vEventObject);
        }

        break;

      case "mouseout":
        if (qx.OO.isAvailable("qx.manager.object.ToolTipManager")) {
          qx.manager.object.ToolTipManager.getInstance().handleMouseOut(vEventObject);
        }

        break;

      case "mousewheel":
        // priority for the real target not the (eventually captured) dispatch target
        vReturnValue ? this._onmousewheel(vOriginalTarget || vDispatchTarget, vEventObject) : qx.event.handler.EventHandler.stopDomEvent(vDomEvent);

        break;
    }



    this._ignoreWindowBlur = vType === "mousedown";




    // Send Event Object to Drag&Drop Manager
    if (qx.OO.isAvailable("qx.event.handler.DragAndDropHandler") && vTarget) {
      qx.event.handler.DragAndDropHandler.getInstance().handleMouseEvent(vEventObject);
    }




    // Dispose Event Object
    vEventObject.dispose();
    vEventObject = null;




    // Flush Queues
    qx.ui.core.Widget.flushGlobalQueues();


    // Fix Click (Gecko Bug, see above)
    if (vFixClick)
    {
      this._onmouseevent_post(vDomEvent, "click", this._lastMouseDownDomTarget);

      this._lastMouseDownDomTarget = null;
      this._lastMouseDownDispatchTarget = null;
    }
  }
  catch(ex)
  {
    return this.error("Failed to handle mouse event", ex);
  }
}

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._onmousewheel = function(vTarget, vEvent)
  {
    if(vTarget == null) {
      return;
    }

    // ingore if overflow is configured as hidden
    // in this case send the event to the parent instead
    if(vTarget.getOverflowY() == "hidden") {
      return this._onmousewheel(vTarget.getParent(), vEvent);
    }

    var vScrollTop = vTarget.getScrollTop();
    var vDelta = 20 * vEvent.getWheelDelta();

    // if already at the top edge and the user scrolls up
    // then send the event to the parent instead
    if(vScrollTop == 0 && vDelta > 0) {
      return this._onmousewheel(vTarget.getParent(), vEvent);
    }

    var vScrollHeight = vTarget.getScrollHeight();
    var vClientHeight = vTarget.getClientHeight();

    // if already at the bottom edge and the user scrolls down
    // then send the event to the parent instead
    if(vScrollTop + vClientHeight >= vScrollHeight && vDelta < 0) {
      return this._onmousewheel(vTarget.getParent(), vEvent);
    }

    // apply new scroll position
    vTarget.setScrollTop(vScrollTop - vDelta);

    // stop default handling, that works sometimes, too
    vEvent.preventDefault();
  }
}
else
{
  qx.Proto._onmousewheel = function() {};
}







/*
---------------------------------------------------------------------------
  DRAG EVENTS

    Currently only to stop non needed events
---------------------------------------------------------------------------
*/

qx.Proto._ondragevent = function(vEvent)
{
  if (!vEvent) {
    vEvent = window.event;
  }

  qx.event.handler.EventHandler.stopDomEvent(vEvent);
}







/*
---------------------------------------------------------------------------
  SELECT EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._onselectevent = function(e)
{
  if(!e) {
    e = window.event;
  }

  var vTarget = qx.event.handler.EventHandler.getOriginalTargetObjectFromEvent(e);

  if(vTarget && !vTarget.getSelectable()) {
    qx.event.handler.EventHandler.stopDomEvent(e);
  }
}






/*
---------------------------------------------------------------------------
  WINDOW EVENTS
---------------------------------------------------------------------------
*/

qx.Proto._focused = false;

qx.Proto._onwindowblur = function(e)
{
  // this.debug("Try Window blur...");

  if (!this._focused || this._ignoreWindowBlur) {
    return;
  }

  this._focused = false;

  // this.debug("Window blur...");

  // Disable capturing
  this.setCaptureWidget(null);

  // Hide Popups, Tooltips, ...
  if (qx.OO.isAvailable("qx.manager.object.PopupManager")) {
    qx.manager.object.PopupManager.getInstance().update();
  }

  // Hide Menus
  if (qx.OO.isAvailable("qx.manager.object.MenuManager")) {
    qx.manager.object.MenuManager.getInstance().update();
  }

  // Cancel Drag Operations
  if (qx.OO.isAvailable("qx.event.handler.DragAndDropHandler")) {
    qx.event.handler.DragAndDropHandler.getInstance().globalCancelDrag();
  }

  // Send blur event to client document
  qx.ui.core.ClientDocument.getInstance().createDispatchEvent("windowblur");
}

qx.Proto._onwindowfocus = function(e)
{
  // this.debug("Try Window focus...");

  if (this._focused) {
    return;
  }

  this._focused = true;

  // this.debug("Window focus...");

  // Send focus event to client document
  qx.ui.core.ClientDocument.getInstance().createDispatchEvent("windowfocus");
}

qx.Proto._onwindowresize = function(e)
{
  // Send resize event to client document
  qx.ui.core.ClientDocument.getInstance().createDispatchEvent("windowresize");
}





/*
---------------------------------------------------------------------------
  DISPOSE
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  // Detach mouse events
  this.detachEvents();

  // Reset functions
  this.__onmouseevent = this.__ondragevent = this.__onselectevent = null;
  this.__onwindowblur = this.__onwindowfocus = this.__onwindowresize = null;

  // Cleanup
  this._lastMouseEventType = null;
  this._lastMouseDown = null;
  this._lastMouseEventDate = null;

  this._lastMouseDownDomTarget = null;
  this._lastMouseDownDispatchTarget = null;

  if (this._commands)
  {
    for (var vHash in this._commands)
    {
      this._commands[vHash].dispose();
      delete this._commands[vHash];
    }

    this._commands = null;
  }

  qx.core.Target.prototype.dispose.call(this);
}






/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
