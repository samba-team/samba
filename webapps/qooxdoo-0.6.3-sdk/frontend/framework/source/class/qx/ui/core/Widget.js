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
#require(qx.renderer.color.ColorCache)
#require(qx.renderer.border.BorderCache)
#require(qx.manager.object.AppearanceManager)
#after(qx.component.init.InterfaceInitComponent)
#optional(qx.ui.core.Parent)
#optional(qx.ui.form.Button)
#optional(qx.client.Timer)
#optional(qx.client.Command)
#optional(qx.ui.popup.ToolTip)
#optional(qx.ui.menu.Menu)
#optional(qx.ui.basic.Inline)

************************************************************************ */

/**
 * This is the main widget, all visible objects in the application extend this.
 *
 * @event beforeAppear {qx.event.type.Event}
 * @event appear {qx.event.type.Event}
 * @event beforeDisappear {qx.event.type.Event}
 * @event disappear {qx.event.type.Event}
 * @event beforeInsertDom {qx.event.type.Event}
 * @event insertDom {qx.event.type.Event}
 * @event beforeRemoveDom {qx.event.type.Event}
 * @event removeDom {qx.event.type.Event}
 * @event create {qx.event.type.Event}
 * @event execute {qx.event.type.Event}
 * @event FADE_FINISHED {qx.event.type.DataEvent}
 * @event mouseover {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event mousemove {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event mouseout {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event mousedown {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event mouseup {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event mousewheel {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event click {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event dblclick {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event contextmenu {qx.event.type.MouseEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event keydown {qx.event.type.KeyEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event keypress {qx.event.type.KeyEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event keyinput {qx.event.type.KeyEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event keyup {qx.event.type.KeyEvent} (Fired by {@link qx.event.handler.EventHandler})
 * @event focusout {qx.event.type.FocusEvent} (Fired by {@link qx.ui.core.Parent})
 * @event focusin {qx.event.type.FocusEvent} (Fired by {@link qx.ui.core.Parent})
 * @event blur {qx.event.type.FocusEvent} (Fired by {@link qx.ui.core.Parent})
 * @event focus {qx.event.type.FocusEvent} (Fired by {@link qx.ui.core.Parent})
 */
qx.OO.defineClass("qx.ui.core.Widget", qx.core.Target,
function()
{
  if (this.classname == qx.ui.core.Widget.ABSTRACT_CLASS) {
    throw new Error("Please omit the usage of qx.ui.core.Widget directly. Choose between qx.ui.core.Parent and qx.ui.basic.Terminator instead!");
  }

  qx.core.Target.call(this, true);


  // ************************************************************************
  //   HTML MAPPING DATA STRUCTURES
  // ************************************************************************
  // Allows the user to setup styles and attributes without a
  // need to have the target element created already.
  /*
  this._htmlProperties = { className : this.classname }
  this._htmlAttributes = { qxhashcode : this._hashCode }
  */
  this._styleProperties = { position : "absolute" }


  // ************************************************************************
  //   LAYOUT CHANGES
  // ************************************************************************
  this._layoutChanges = {};


  // ************************************************************************
  //   APPEARANCE
  // ************************************************************************
  this._states = {};
  this._applyInitialAppearance();
});

qx.Class.ABSTRACT_CLASS = "qx.ui.core.Widget";

// Will be calculated later (TODO: Move to qx.Dom?)
qx.Class.SCROLLBAR_SIZE = 16;





/*
---------------------------------------------------------------------------
  DEFAULT SETTINGS
---------------------------------------------------------------------------
*/

qx.Settings.setDefault("enableQueueDebug", false);






/*
---------------------------------------------------------------------------
  BASIC PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The parent widget (the real object, no ID or something)
*/
qx.OO.addProperty({ name : "parent", type : "object", instance : "qx.ui.core.Parent", defaultValue : null });

/*!
  The element node (if the widget is created, otherwise null)
*/
qx.OO.addProperty({ name : "element" });

/*!
  Simple and fast switch of the visibility of a widget.
*/
qx.OO.addProperty({ name : "visibility", type : "boolean", defaultValue : true });

/*!
  If the widget should be displayed. Use this property instead of visibility if the change
  in visibility should have effects on the parent widget.
*/
qx.OO.addProperty({ name : "display", type : "boolean", defaultValue : true });

/*!
  If you switch this to true, the widget doesn't handle
  events directly. It will redirect them to the parent
  widget.
*/
qx.OO.addProperty({ name : "anonymous", type : "boolean", defaultValue : false, getAlias : "isAnonymous" });

/*!
  The tagname of the element which should automatically be created
*/
qx.OO.addProperty({ name : "tagName", type : "string", defaultValue : "div" });

/*!
  This is used by many layout managers to control the individual horizontal alignment of this widget inside this parent.

  This should be used with caution since in some cases
  this might give unrespected results.
*/
qx.OO.addProperty({ name : "horizontalAlign", type : "string" });

/*!
  This is used by many layout managers to control the individual vertical alignment of this widget inside this parent.

  This should be used with caution since in some cases
  this might give unrespected results.
*/
qx.OO.addProperty({ name : "verticalAlign", type : "string" });

/*!
  Should this widget be stretched on the x-axis if the layout handler will do this?
  Used by some layout handlers (qx.ui.layout.BoxLayout, ...).
*/
qx.OO.addProperty({ name : "allowStretchX", type : "boolean", defaultValue : true });

/*!
  Should this widget be stretched on the y-axis if the layout handler will do this?
  Used by some layout handlers (qx.ui.layout.BoxLayout, ...).
*/
qx.OO.addProperty({ name : "allowStretchY", type : "boolean", defaultValue : true });






/*
---------------------------------------------------------------------------
  STYLE PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Mapping to native style property z-index.

  This should be used with caution since in some cases
  this might give unrespected results.
*/
qx.OO.addProperty({ name : "zIndex", type : "number" });

/*!
  The backgroundColor style property of the rendered widget.
  As input are allowed any instance of qx.renderer.color.Color or a string which defines the color itself.
*/
qx.OO.addProperty({ name : "backgroundColor", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache, allowMultipleArguments : true });

/*!
  The color style property of the rendered widget.
  As input are allowed any instance of qx.renderer.color.Color or a string which defines the color itself.
*/
qx.OO.addProperty({ name : "color", type : "object", instance : "qx.renderer.color.Color", convert : qx.renderer.color.ColorCache, allowMultipleArguments : true });

/*!
  The border property describes how to paint the border on the widget.

  This should be used with caution since in some cases (mostly complex widgets)
  this might give unrespected results.
*/
qx.OO.addProperty({ name : "border", type : "object", instance : "qx.renderer.border.Border", convert : qx.renderer.border.BorderCache, allowMultipleArguments : true });

/*!
  Mapping to native style property opacity.

  The uniform opacity setting to be applied across an entire object. Behaves like the new CSS-3 Property.
  Any values outside the range 0.0 (fully transparent) to 1.0 (fully opaque) will be clamped to this range.
*/
qx.OO.addProperty({ name : "opacity", type : "number" });

/*!
  Mapping to native style property cursor.

  The name of the cursor to show when the mouse pointer is over the widget.
  This is any valid CSS2 cursor name defined by W3C.

  The following values are possible:
  <ul><li>default</li>
  <li>crosshair</li>
  <li>pointer (hand is the ie name and will mapped to pointer in non-ie).</li>
  <li>move</li>
  <li>n-resize</li>
  <li>ne-resize</li>
  <li>e-resize</li>
  <li>se-resize</li>
  <li>s-resize</li>
  <li>sw-resize</li>
  <li>w-resize</li>
  <li>nw-resize</li>
  <li>text</li>
  <li>wait</li>
  <li>help </li>
  <li>url([file]) = self defined cursor, file should be an ANI- or CUR-type</li>
  </ul>
*/
qx.OO.addProperty({ name : "cursor", type : "string" });

/*!
  Mapping to native style property background-image.

  The URI of the image file to use as background image.
*/
qx.OO.addProperty({ name : "backgroundImage", type : "string" });

/**
 * Describes how to handle content that is too large to fit inside the widget.
 *
 * Overflow modes:
 * * hidden: The content is clipped
 * * auto: Scroll bars are shown as needed
 * * scroll: Scroll bars are always shown. Even if there is enough room for the content inside the widget.
 * * scrollX: Scroll bars for the X-Axis are always shown. Even if there is enough room for the content inside the widget.
 * * scrollY: Scroll bars for the Y-Axis are always shown. Even if there is enough room for the content inside the widget.
 */
qx.OO.addProperty({ name : "overflow", type : "string", addToQueue : true });

/*!
  Clipping of the widget (left)
*/
qx.OO.addProperty({ name : "clipLeft", type : "number", impl : "clip" });

/*!
  Clipping of the widget (top)
*/
qx.OO.addProperty({ name : "clipTop", type : "number", impl : "clip" });

/*!
  Clipping of the widget (width)
*/
qx.OO.addProperty({ name : "clipWidth", type : "number", impl : "clip" });

/*!
  Clipping of the widget (height)
*/
qx.OO.addProperty({ name : "clipHeight", type : "number", impl : "clip" });







/*
---------------------------------------------------------------------------
  MANAGMENT PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Set this to a positive value makes the widget able to get the focus.
  It even is reachable through the usage of the tab-key.

  Widgets with the same tabIndex are handled through there position
  in the document.
*/
qx.OO.addProperty({ name : "tabIndex", type : "number", defaultValue : -1 });

/*!
  If the focus outline should be hidden.
*/
qx.OO.addProperty({ name : "hideFocus", type : "boolean", defaultValue : false });

/*!
  Use DOM focussing (focus() and blur() methods of DOM nodes)
*/
qx.OO.addProperty({ name : "enableElementFocus", type : "boolean", defaultValue : true });

/*!
  Handle focus state of this widget.

  someWidget.setFocused(true) set the current focus to this widget.
  someWidget.setFocused(false) remove the current focus and leave it blank.

  Normally you didn't need to set this directly.
*/
qx.OO.addProperty({ name : "focused", type : "boolean", defaultValue : false });

/*!
  Toggle the possibility to select the element of this widget.
*/
qx.OO.addProperty({ name : "selectable", type : "boolean", defaultValue : true, getAlias : "isSelectable" });

/*!
  Contains the tooltip object connected to the widget.
*/
qx.OO.addProperty({ name : "toolTip", type : "object", instance : "qx.ui.popup.ToolTip" });

/*!
  Contains the context menu object connected to the widget. (Need real implementation)
*/
qx.OO.addProperty({ name : "contextMenu", type : "object", instance : "qx.ui.menu.Menu" });

/*!
  Capture all events and map them to this widget
*/
qx.OO.addProperty({ name : "capture", type : "boolean", defaultValue : false });

/*!
  Contains the support drop types for drag and drop support
*/
qx.OO.addProperty({ name : "dropDataTypes" });

/*!
  A command called if the widget should be excecuted (a placeholder for buttons, ...)
*/
qx.OO.addProperty({ name : "command", type : "object", instance : "qx.client.Command" });

/*!
  Appearance of the widget
*/
qx.OO.addProperty({ name : "appearance", type : "string" });






/*
---------------------------------------------------------------------------
  MARGIN/PADDING PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Margin of the widget (top)
*/
qx.OO.addProperty({ name : "marginTop", type : "number", addToQueue : true, impl : "marginY" });

/*!
  Margin of the widget (right)
*/
qx.OO.addProperty({ name : "marginRight", type : "number", addToQueue : true, impl : "marginX" });

/*!
  Margin of the widget (bottom)
*/
qx.OO.addProperty({ name : "marginBottom", type : "number", addToQueue : true, impl : "marginY" });

/*!
  Margin of the widget (left)
*/
qx.OO.addProperty({ name : "marginLeft", type : "number", addToQueue : true, impl : "marginX" });


/*!
  Padding of the widget (top)
*/
qx.OO.addProperty({ name : "paddingTop", type : "number", addToQueue : true, impl : "paddingY" });

/*!
  Padding of the widget (right)
*/
qx.OO.addProperty({ name : "paddingRight", type : "number", addToQueue : true, impl : "paddingX" });

/*!
  Padding of the widget (bottom)
*/
qx.OO.addProperty({ name : "paddingBottom", type : "number", addToQueue : true, impl : "paddingY" });

/*!
  Padding of the widget (left)
*/
qx.OO.addProperty({ name : "paddingLeft", type : "number", addToQueue : true, impl : "paddingX" });







/*
---------------------------------------------------------------------------
  HORIZONAL DIMENSION PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The distance from the outer left border to the parent left area edge.

  You could only set two of the three horizonal dimension properties (boxLeft, boxRight, boxWidth)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "left", addToQueue : true, unitDetection : "pixelPercent" });

/*!
  The distance from the outer right border to the parent right area edge.

  You could only set two of the three horizonal dimension properties (boxLeft, boxRight, boxWidth)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "right", addToQueue : true, unitDetection : "pixelPercent" });

/*!
  The width of the box (including padding and border).

  You could only set two of the three horizonal dimension properties (boxLeft, boxRight, boxWidth)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "width", addToQueue : true, unitDetection : "pixelPercentAutoFlex" });

/*!
  The minimum width of the box (including padding and border).

  Set this to omit the shrinking of the box width under this value.
*/
qx.OO.addProperty({ name : "minWidth", addToQueue : true, unitDetection : "pixelPercentAuto" });

/*!
  The maximum width of the box (including padding and border).

  Set this to omit the expanding of the box width above this value.
*/
qx.OO.addProperty({ name : "maxWidth", addToQueue : true, unitDetection : "pixelPercentAuto" });







/*
---------------------------------------------------------------------------
  VERTICAL DIMENSION PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The distance from the outer top border to the parent top area edge.

  You could only set two of the three vertical dimension properties (boxTop, boxBottom, boxHeight)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "top", addToQueue : true, unitDetection : "pixelPercent" });

/*!
  The distance from the outer bottom border to the parent bottom area edge.

  You could only set two of the three vertical dimension properties (boxTop, boxBottom, boxHeight)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "bottom", addToQueue : true, unitDetection : "pixelPercent" });

/*!
  The height of the box (including padding and border).

  You could only set two of the three vertical dimension properties (boxTop, boxBottom, boxHeight)
  at the same time. This will be omitted during the setup of the new third value. To reset a value
  you didn't want anymore, set it to null.
*/
qx.OO.addProperty({ name : "height", addToQueue : true, unitDetection : "pixelPercentAutoFlex" });

/*!
  The minimum height of the box (including padding and border).

  Set this to omit the shrinking of the box height under this value.
*/
qx.OO.addProperty({ name : "minHeight", addToQueue : true, unitDetection : "pixelPercentAuto" });

/*!
  The maximum height of the box (including padding and border).

  Set this to omit the expanding of the box height above this value.
*/
qx.OO.addProperty({ name : "maxHeight", addToQueue : true, unitDetection : "pixelPercentAuto" });







/*
---------------------------------------------------------------------------
  PROPERTY GROUPS
---------------------------------------------------------------------------
*/

qx.OO.addPropertyGroup({ name : "location", members : [ "left", "top" ]});
qx.OO.addPropertyGroup({ name : "dimension", members : [ "width", "height" ]});

qx.OO.addPropertyGroup({ name : "space", members : [ "left", "width", "top", "height" ]});
qx.OO.addPropertyGroup({ name : "edge", members : [ "top", "right", "bottom", "left" ], mode : "shorthand" });

qx.OO.addPropertyGroup({ name : "padding", members : [ "paddingTop", "paddingRight", "paddingBottom", "paddingLeft" ], mode: "shorthand" });
qx.OO.addPropertyGroup({ name : "margin", members : [ "marginTop", "marginRight", "marginBottom", "marginLeft" ], mode: "shorthand" });

qx.OO.addPropertyGroup({ name : "heights", members : [ "minHeight", "height", "maxHeight" ]});
qx.OO.addPropertyGroup({ name : "widths", members : [ "minWidth", "width", "maxWidth" ]});

qx.OO.addPropertyGroup({ name : "align", members : [ "horizontalAlign", "verticalAlign" ]});
qx.OO.addPropertyGroup({ name : "stretch", members : [ "stretchX", "stretchY" ]});

qx.OO.addPropertyGroup({ name : "clipLocation", members : [ "clipLeft", "clipTop" ]});
qx.OO.addPropertyGroup({ name : "clipDimension", members : [ "clipWidth", "clipHeight" ]});
qx.OO.addPropertyGroup({ name : "clip", members : [ "clipLeft", "clipTop", "clipWidth", "clipHeight" ]});








/* ************************************************************************
   Class data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  ALL QUEUES
---------------------------------------------------------------------------
*/

if (qx.Settings.getValueOfClass("qx.ui.core.Widget", "enableQueueDebug"))
{
  qx.ui.core.Widget.flushGlobalQueues = function()
  {
    if (qx.ui.core.Widget._inFlushGlobalQueues || !qx.core.Init.getInstance().getComponent().isUiReady()) {
      return;
    }

    if (!(qx.ui.core.Widget._globalWidgetQueue.length > 0 || qx.ui.core.Widget._globalElementQueue.length > 0 ||
        qx.ui.core.Widget._globalStateQueue.length > 0  || qx.ui.core.Widget._globalJobQueue.length > 0 ||
        qx.ui.core.Widget._globalLayoutQueue.length > 0 || qx.ui.core.Widget._fastGlobalDisplayQueue.length > 0 ||
        !qx.lang.Object.isEmpty(qx.ui.core.Widget._lazyGlobalDisplayQueue))) {
      return;
    }

    var globalWidgetQueueLength      = qx.ui.core.Widget._globalWidgetQueue.length;
    var globalElementQueueLength     = qx.ui.core.Widget._globalElementQueue.length;
    var globalStateQueueLength       = qx.ui.core.Widget._globalStateQueue.length;
    var globalJobQueueLength         = qx.ui.core.Widget._globalJobQueue.length;
    var globalLayoutQueueLength      = qx.ui.core.Widget._globalLayoutQueue.length;
    var fastGlobalDisplayQueueLength = qx.ui.core.Widget._fastGlobalDisplayQueue.length;
    var lazyGlobalDisplayQueueLength = qx.ui.core.Widget._lazyGlobalDisplayQueue ? qx.ui.core.Widget._lazyGlobalDisplayQueue.length : 0;

    // Also used for inline event handling to seperate 'real' events
    qx.ui.core.Widget._inFlushGlobalQueues = true;

    var vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalWidgetQueue();
    var vWidgetDuration = (new Date).valueOf() - vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalStateQueue();
    var vStateDuration = (new Date).valueOf() - vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalElementQueue();
    var vElementDuration = (new Date).valueOf() - vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalJobQueue();
    var vJobDuration = (new Date).valueOf() - vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalLayoutQueue();
    var vLayoutDuration = (new Date).valueOf() - vStart;

    vStart = (new Date).valueOf();
    qx.ui.core.Widget.flushGlobalDisplayQueue();
    var vDisplayDuration = (new Date).valueOf() - vStart;

    var vSum = vWidgetDuration + vStateDuration + vElementDuration + vJobDuration + vLayoutDuration + vDisplayDuration;

    if (vSum > 0)
    {
      var logger = qx.dev.log.Logger.getClassLogger(qx.ui.core.Widget);
      logger.debug("Flush Global Queues");
      logger.debug("Widgets: " + vWidgetDuration + "ms (" + globalWidgetQueueLength + ")");
      logger.debug("State: " + vStateDuration + "ms (" + globalStateQueueLength + ")");
      logger.debug("Element: " + vElementDuration + "ms (" + globalElementQueueLength + ")");
      logger.debug("Job: " + vJobDuration + "ms (" + globalJobQueueLength + ")");
      logger.debug("Layout: " + vLayoutDuration + "ms (" + globalLayoutQueueLength + ")");
      logger.debug("Display: " + vDisplayDuration + "ms (fast:" + fastGlobalDisplayQueueLength + ",lazy:" + lazyGlobalDisplayQueueLength + ")");

      window.status = "Flush: Widget:" + vWidgetDuration + " State:" + vStateDuration + " Element:" + vElementDuration + " Job:" + vJobDuration + " Layout:" + vLayoutDuration + " Display:" + vDisplayDuration;
    }

    delete qx.ui.core.Widget._inFlushGlobalQueues;
  }
}
else
{
  qx.ui.core.Widget.flushGlobalQueues = function()
  {
    if (qx.ui.core.Widget._inFlushGlobalQueues || !qx.core.Init.getInstance().getComponent().isUiReady()) {
      return;
    }

    // Also used for inline event handling to seperate 'real' events
    qx.ui.core.Widget._inFlushGlobalQueues = true;

    qx.ui.core.Widget.flushGlobalWidgetQueue();
    qx.ui.core.Widget.flushGlobalStateQueue();
    qx.ui.core.Widget.flushGlobalElementQueue();
    qx.ui.core.Widget.flushGlobalJobQueue();
    qx.ui.core.Widget.flushGlobalLayoutQueue();
    qx.ui.core.Widget.flushGlobalDisplayQueue();

    delete qx.ui.core.Widget._inFlushGlobalQueues;
  }
}






/*
---------------------------------------------------------------------------
  WIDGET QUEUE

  Allows widgets to register to the widget queue to do multiple things
  before the other queues will be flushed
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._globalWidgetQueue = [];

qx.ui.core.Widget.addToGlobalWidgetQueue = function(vWidget)
{
  if (!vWidget._isInGlobalWidgetQueue && vWidget._isDisplayable)
  {
    qx.ui.core.Widget._globalWidgetQueue.push(vWidget);
    vWidget._isInGlobalWidgetQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalWidgetQueue = function(vWidget)
{
  if (vWidget._isInGlobalWidgetQueue)
  {
    qx.lang.Array.remove(qx.ui.core.Widget._globalWidgetQueue, vWidget);
    delete vWidget._isInGlobalWidgetQueue;
  }
}

qx.ui.core.Widget.flushGlobalWidgetQueue = function()
{
  var vQueue=qx.ui.core.Widget._globalWidgetQueue, vLength, vWidget;

  while ((vLength=vQueue.length) > 0)
  {
    for (var i=0; i<vLength; i++)
    {
      vWidget = vQueue[i];

      vWidget.flushWidgetQueue();
      delete vWidget._isInGlobalWidgetQueue;
    }

    vQueue.splice(0, vLength);
  }
}









/*
---------------------------------------------------------------------------
  ELEMENT QUEUE

  Contains the widgets which should be (dom-)created
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._globalElementQueue = [];

qx.ui.core.Widget.addToGlobalElementQueue = function(vWidget)
{
  if (!vWidget._isInGlobalElementQueue && vWidget._isDisplayable)
  {
    qx.ui.core.Widget._globalElementQueue.push(vWidget);
    vWidget._isInGlobalElementQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalElementQueue = function(vWidget)
{
  if (vWidget._isInGlobalElementQueue)
  {
    qx.lang.Array.remove(qx.ui.core.Widget._globalElementQueue, vWidget);
    delete vWidget._isInGlobalElementQueue;
  }
}

qx.ui.core.Widget.flushGlobalElementQueue = function()
{
  var vQueue=qx.ui.core.Widget._globalElementQueue, vLength, vWidget;

  while ((vLength=vQueue.length) > 0)
  {
    for (var i=0; i<vLength; i++)
    {
      vWidget = vQueue[i];

      vWidget._createElementImpl();
      delete vWidget._isInGlobalElementQueue;
    }

    vQueue.splice(0, vLength);
  }
}






/*
---------------------------------------------------------------------------
  STATE QUEUE

  Contains the widgets which recently changed their state
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._globalStateQueue = [];

qx.ui.core.Widget.addToGlobalStateQueue = function(vWidget)
{
  if (!vWidget._isInGlobalStateQueue && vWidget._isDisplayable)
  {
    qx.ui.core.Widget._globalStateQueue.push(vWidget);
    vWidget._isInGlobalStateQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalStateQueue = function(vWidget)
{
  if (vWidget._isInGlobalStateQueue)
  {
    qx.lang.Array.remove(qx.ui.core.Widget._globalStateQueue, vWidget);
    delete vWidget._isInGlobalStateQueue;
  }
}

qx.ui.core.Widget.flushGlobalStateQueue = function()
{
  var vQueue=qx.ui.core.Widget._globalStateQueue, vLength, vWidget;

  while ((vLength=vQueue.length) > 0)
  {
    for (var i=0; i<vLength; i++)
    {
      vWidget = vQueue[i];

      vWidget._applyStateAppearance();

      delete vWidget._isInGlobalStateQueue;
    }

    vQueue.splice(0, vLength);
  }
}







/*
---------------------------------------------------------------------------
  JOBS QUEUE

  Contains the widgets which need a update after they were visible before
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._globalJobQueue = [];

qx.ui.core.Widget.addToGlobalJobQueue = function(vWidget)
{
  if (!vWidget._isInGlobalJobQueue && vWidget._isDisplayable)
  {
    qx.ui.core.Widget._globalJobQueue.push(vWidget);
    vWidget._isInGlobalJobQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalJobQueue = function(vWidget)
{
  if (vWidget._isInGlobalJobQueue)
  {
    qx.lang.Array.remove(qx.ui.core.Widget._globalJobQueue, vWidget);
    delete vWidget._isInGlobalJobQueue;
  }
}

qx.ui.core.Widget.flushGlobalJobQueue = function()
{
  var vQueue=qx.ui.core.Widget._globalJobQueue, vLength, vWidget;

  while ((vLength=vQueue.length) > 0)
  {
    for (var i=0; i<vLength; i++)
    {
      vWidget = vQueue[i];

      vWidget._flushJobQueue(vWidget._jobQueue);
      delete vWidget._isInGlobalJobQueue;
    }

    vQueue.splice(0, vLength);
  }
}






/*
---------------------------------------------------------------------------
  LAYOUT QUEUE

  Contains the parents (qx.ui.core.Parent) of the children which needs layout updates
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._globalLayoutQueue = [];

qx.ui.core.Widget.addToGlobalLayoutQueue = function(vParent)
{
  if (!vParent._isInGlobalLayoutQueue && vParent._isDisplayable)
  {
    qx.ui.core.Widget._globalLayoutQueue.push(vParent);
    vParent._isInGlobalLayoutQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalLayoutQueue = function(vParent)
{
  if (vParent._isInGlobalLayoutQueue)
  {
    qx.lang.Array.remove(qx.ui.core.Widget._globalLayoutQueue, vParent);
    delete vParent._isInGlobalLayoutQueue;
  }
}

qx.ui.core.Widget.flushGlobalLayoutQueue = function()
{
  var vQueue=qx.ui.core.Widget._globalLayoutQueue, vLength, vParent;

  while ((vLength=vQueue.length) > 0)
  {
    for (var i=0; i<vLength; i++)
    {
      vParent = vQueue[i];

      vParent._flushChildrenQueue();
      delete vParent._isInGlobalLayoutQueue;
    }

    vQueue.splice(0, vLength);
  }
}







/*
---------------------------------------------------------------------------
  DISPLAY QUEUE

  Contains the widgets which should initially become visible
---------------------------------------------------------------------------
*/

qx.ui.core.Widget._fastGlobalDisplayQueue = [];
qx.ui.core.Widget._lazyGlobalDisplayQueues = {};

qx.ui.core.Widget.addToGlobalDisplayQueue = function(vWidget)
{
  if (!vWidget._isInGlobalDisplayQueue && vWidget._isDisplayable)
  {
    var vParent = vWidget.getParent();

    if (vParent.isSeeable())
    {
      var vKey = vParent.toHashCode();

      if (qx.ui.core.Widget._lazyGlobalDisplayQueues[vKey])
      {
        qx.ui.core.Widget._lazyGlobalDisplayQueues[vKey].push(vWidget);
      }
      else
      {
        qx.ui.core.Widget._lazyGlobalDisplayQueues[vKey] = [vWidget];
      }
    }
    else
    {
      qx.ui.core.Widget._fastGlobalDisplayQueue.push(vWidget);
    }

    vWidget._isInGlobalDisplayQueue = true;
  }
}

qx.ui.core.Widget.removeFromGlobalDisplayQueue = function(vWidget) {}

qx.ui.core.Widget.flushGlobalDisplayQueue = function()
{
  var vKey, vLazyQueue, vWidget, vFragment;

  var vFastQueue = qx.ui.core.Widget._fastGlobalDisplayQueue;
  var vLazyQueues = qx.ui.core.Widget._lazyGlobalDisplayQueues;




  /* -----------------------------------------------
      Flush display queues
  ----------------------------------------------- */

  // Work on fast queue
  for (var i=0, l=vFastQueue.length; i<l; i++)
  {
    vWidget = vFastQueue[i];
    vWidget.getParent()._getTargetNode().appendChild(vWidget.getElement());
  }


  // Work on lazy queues: Inline widgets
  if (qx.OO.isAvailable("qx.ui.basic.Inline"))
  {
    for (vKey in vLazyQueues)
    {
      vLazyQueue = vLazyQueues[vKey];

      for (var i=0; i<vLazyQueue.length; i++)
      {
        vWidget = vLazyQueue[i];

        if (vWidget instanceof qx.ui.basic.Inline)
        {
          vWidget._beforeInsertDom();

          try
          {
            document.getElementById(vWidget.getInlineNodeId()).appendChild(vWidget.getElement());
          }
          catch(ex)
          {
            vWidget.debug("Could not append to inline id: " + vWidget.getInlineNodeId(), ex);
          }

          vWidget._afterInsertDom();
          vWidget._afterAppear();

          // Remove inline widget from queue and fix iterator position
          qx.lang.Array.remove(vLazyQueue, vWidget);
          i--;

          // Reset display queue flag
          delete vWidget._isInGlobalDisplayQueue;
        }
      }
    }
  }


  // Work on lazy queues: Other widgets
  for (vKey in vLazyQueues)
  {
    vLazyQueue = vLazyQueues[vKey];

    // Speed enhancement: Choose a fairly small arbitrary value for the number
    // of elements that should be added to the parent individually.  If more
    // than this number of elements is to be added to the parent, we'll create
    // a document fragment, add the elements to the document fragment, and
    // then add the whole fragment to the parent en mass (assuming that
    // creation of a document fragment is supported by the browser).
    if (document.createDocumentFragment && vLazyQueue.length >= 3)
    {
      // creating new document fragment
      vFragment = document.createDocumentFragment();

      // appending all widget elements to fragment
      for (var i=0, l=vLazyQueue.length; i<l; i++)
      {
        vWidget = vLazyQueue[i];

        vWidget._beforeInsertDom();
        vFragment.appendChild(vWidget.getElement());
      }

      // append all fragment data at once to
      // the already visible parent widget element
      vLazyQueue[0].getParent()._getTargetNode().appendChild(vFragment);

      for (var i=0, l=vLazyQueue.length; i<l; i++)
      {
        vWidget = vLazyQueue[i];
        vWidget._afterInsertDom();
      }
    }
    else
    {
      // appending all widget elements (including previously added children)
      // to the already visible parent widget element
      for (var i=0, l=vLazyQueue.length; i<l; i++)
      {
        vWidget = vLazyQueue[i];

        vWidget._beforeInsertDom();
        vWidget.getParent()._getTargetNode().appendChild(vWidget.getElement());
        vWidget._afterInsertDom();
      }
    }
  }






  /* -----------------------------------------------
      Cleanup and appear signals
  ----------------------------------------------- */

  // Only need to do this with the lazy queues
  // because through the recursion from qx.ui.core.Parent
  // all others get also informed.
  for (vKey in vLazyQueues)
  {
    vLazyQueue = vLazyQueues[vKey];

    for (var i=0, l=vLazyQueue.length; i<l; i++)
    {
      vWidget = vLazyQueue[i];

      if (vWidget.getVisibility()) {
        vWidget._afterAppear();
      }

      // Reset display queue flag
      delete vWidget._isInGlobalDisplayQueue;
    }

    delete vLazyQueues[vKey];
  }

  // Reset display queue flag for widgets in fastQueue
  for (var i=0, l=vFastQueue.length; i<l; i++) {
    delete vFastQueue[i]._isInGlobalDisplayQueue;
  }

  // Remove fast queue entries
  qx.lang.Array.removeAll(vFastQueue);
}








/*
---------------------------------------------------------------------------
  GLOBAL HELPERS
---------------------------------------------------------------------------
*/

qx.ui.core.Widget.getActiveSiblingHelperIgnore = function(vIgnoreClasses, vInstance)
{
  for (var j=0; j<vIgnoreClasses.length; j++) {
    if (vInstance instanceof vIgnoreClasses[j]) {
      return true;
    }
  }

  return false;
}

qx.ui.core.Widget.getActiveSiblingHelper = function(vObject, vParent, vCalc, vIgnoreClasses, vMode)
{
  if (!vIgnoreClasses) {
    vIgnoreClasses = [];
  }

  var vChilds = vParent.getChildren();
  var vPosition = qx.util.Validation.isInvalid(vMode) ? vChilds.indexOf(vObject) + vCalc : vMode == "first" ? 0 : vChilds.length-1;
  var vInstance = vChilds[vPosition];

  while(!vInstance.isEnabled() || qx.ui.core.Widget.getActiveSiblingHelperIgnore(vIgnoreClasses, vInstance))
  {
    vPosition += vCalc;
    vInstance = vChilds[vPosition];

    if (!vInstance) {
      return null;
    }
  }

  return vInstance;
}







/* ************************************************************************
   Instance data, properties and methods
************************************************************************ */

/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

/*!
  If the widget is visible and rendered on the screen.
*/
qx.Proto.isMaterialized = function() {
  var el=this._element;
  return (this._initialLayoutDone &&
          this._isDisplayable &&
          qx.dom.Style.getStyleProperty(el, "display") != "none" &&
          qx.dom.Style.getStyleProperty(el, "visibility") != "hidden" &&
          el.offsetWidth > 0 && el.offsetHeight > 0);
}

/*!
  A single setup to the current preferred pixel values of the widget
*/
qx.Proto.pack = function()
{
  this.setWidth(this.getPreferredBoxWidth());
  this.setHeight(this.getPreferredBoxHeight());
}

/*!
  A bounded setup to the preferred width/height of the widget. Keeps in
  sync if the content or requirements of the widget changes
*/
qx.Proto.auto = function()
{
  this.setWidth("auto");
  this.setHeight("auto");
}





/*
---------------------------------------------------------------------------
  CHILDREN HANDLING: ALL
---------------------------------------------------------------------------
*/

/*!
  Get an array of the current children
*/
qx.Proto.getChildren = qx.util.Return.returnNull;

/*!
  Get the number of children
*/
qx.Proto.getChildrenLength = qx.util.Return.returnZero;

/*!
  Get if the widget has any children
*/
qx.Proto.hasChildren = qx.util.Return.returnFalse;

/*!
  Get if the widget has no children
*/
qx.Proto.isEmpty = qx.util.Return.returnTrue;

/*!
  Return the position of the child inside
*/
qx.Proto.indexOf = qx.util.Return.returnNegativeIndex;

/*!
  Test if this widget contains the given widget
*/
qx.Proto.contains = qx.util.Return.returnFalse;






/*
---------------------------------------------------------------------------
  CHILDREN HANDLING: VISIBLE ONES
---------------------------------------------------------------------------
*/

/*!
  Get an array of the current visible children
*/
qx.Proto.getVisibleChildren = qx.util.Return.returnNull;

/*!
  Get the number of children
*/
qx.Proto.getVisibleChildrenLength = qx.util.Return.returnZero;

/*!
  If this widget has visible children
*/
qx.Proto.hasVisibleChildren = qx.util.Return.returnFalse;

/*!
  Check if there are any visible children inside
*/
qx.Proto.isVisibleEmpty = qx.util.Return.returnTrue;





/*
---------------------------------------------------------------------------
  CORE MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._hasParent = false;
qx.Proto._isDisplayable = false;

qx.Proto.isDisplayable = function() {
  return this._isDisplayable;
}

qx.Proto._checkParent = function(propValue, propOldValue, propData)
{
  if (this.contains(propValue)) {
    throw new Error("Could not insert myself into a child " + propValue + "!");
  }

  return propValue;
}

qx.Proto._modifyParent = function(propValue, propOldValue, propData)
{
  if (propOldValue)
  {
    var vOldIndex = propOldValue.getChildren().indexOf(this);

    // Reset cached dimension and location values
    this._computedWidthValue = this._computedMinWidthValue = this._computedMaxWidthValue = this._computedLeftValue = this._computedRightValue = null;
    this._computedHeightValue = this._computedMinHeightValue = this._computedMaxHeightValue = this._computedTopValue = this._computedBottomValue = null;

    this._cachedBoxWidth = this._cachedInnerWidth = this._cachedOuterWidth = null;
    this._cachedBoxHeight = this._cachedInnerHeight = this._cachedOuterHeight = null;

    // Finally remove from children array
    qx.lang.Array.removeAt(propOldValue.getChildren(), vOldIndex);

    // Invalidate visible children cache
    propOldValue._invalidateVisibleChildren();

    // Remove child from old parent's children queue
    propOldValue._removeChildFromChildrenQueue(this);

    // The layouter adds some layout jobs
    propOldValue.getLayoutImpl().updateChildrenOnRemoveChild(this, vOldIndex);

    // Inform job queue
    propOldValue.addToJobQueue("removeChild");

    // Invalidate inner preferred dimensions
    propOldValue._invalidatePreferredInnerDimensions();

    // Store old parent (needed later by _handleDisplayable)
    this._oldParent = propOldValue;
  }

  if (propValue)
  {
    this._hasParent = true;

    if (qx.util.Validation.isValidNumber(this._insertIndex))
    {
      qx.lang.Array.insertAt(propValue.getChildren(), this, this._insertIndex);
      delete this._insertIndex;
    }
    else
    {
      propValue.getChildren().push(this);
    }
  }
  else
  {
    this._hasParent = false;
  }

  return this._handleDisplayable("parent");
}

qx.Proto._modifyDisplay = function(propValue, propOldValue, propData) {
  return this._handleDisplayable("display");
}







/*
---------------------------------------------------------------------------
  DISPLAYBLE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._handleDisplayable = function(vHint)
{
  // Detect changes. Return if there is no change.
  // Also handle the case if the displayable keeps true and the parent
  // was changed then we must not return here.
  var vDisplayable = this._computeDisplayable();
  if (this._isDisplayable == vDisplayable && !(vDisplayable && vHint == "parent")) {
    return true;
  }

  this._isDisplayable = vDisplayable;

  var vParent = this.getParent();

  // Invalidate visible children
  if (vParent)
  {
    vParent._invalidateVisibleChildren();
    vParent._invalidatePreferredInnerDimensions();
  }

  // Remove old parent's elements from DOM and delete old parent
  if (vHint && this._oldParent && this._oldParent._initialLayoutDone)
  {
    var vElement = this.getElement();
    if(vElement)
    {
      if (this.getVisibility()) {
        this._beforeDisappear();
      }

      this._beforeRemoveDom();

      this._oldParent._getTargetNode().removeChild(vElement);

      this._afterRemoveDom();

      if (this.getVisibility()) {
        this._afterDisappear();
      }
    }

    delete this._oldParent;
  }

  // Handle 'show'
  if (vDisplayable)
  {
    /* --------------------------------
       Update current parent
    -------------------------------- */

    // The layouter added some layout jobs
    if (vParent._initialLayoutDone)
    {
      vParent.getLayoutImpl().updateChildrenOnAddChild(this, vParent.getChildren().indexOf(this));

      // Inform parents job queue
      vParent.addToJobQueue("addChild");
    }

    // Add to parents children queue
    // (indirectly with a new layout request)
    this.addToLayoutChanges("initial");

    // Add to custom queues
    this.addToCustomQueues(vHint);

    // Handle beforeAppear signals
    if (this.getVisibility()) {
      this._beforeAppear();
    }



    /* --------------------------------
       Add to global Queues
    -------------------------------- */

    // Add element (and create if not ready)
    if (!this._isCreated) {
      qx.ui.core.Widget.addToGlobalElementQueue(this);
    }

    // Add to global queues
    qx.ui.core.Widget.addToGlobalStateQueue(this);

    if (!qx.lang.Object.isEmpty(this._jobQueue)) {
      qx.ui.core.Widget.addToGlobalJobQueue(this);
    }

    if (!qx.lang.Object.isEmpty(this._childrenQueue)) {
      qx.ui.core.Widget.addToGlobalLayoutQueue(this);
    }
  }

  // Handle 'hide'
  else
  {
    // Removing from global queues
    qx.ui.core.Widget.removeFromGlobalElementQueue(this);
    qx.ui.core.Widget.removeFromGlobalStateQueue(this);
    qx.ui.core.Widget.removeFromGlobalJobQueue(this);
    qx.ui.core.Widget.removeFromGlobalLayoutQueue(this);

    // Add to top-level tree queue
    this.removeFromCustomQueues(vHint);

    // only remove when itself want to be removed
    // through a property change - not a parent signal
    if (vParent && vHint)
    {
      if (this.getVisibility()) {
        this._beforeDisappear();
      }

      // The layouter added some layout jobs
      if (vParent._initialLayoutDone && this._initialLayoutDone)
      {
        vParent.getLayoutImpl().updateChildrenOnRemoveChild(this, vParent.getChildren().indexOf(this));

        // Inform parent's job queue
        vParent.addToJobQueue("removeChild");

        // Before Remove DOM Event
        this._beforeRemoveDom();

        // DOM action
        vParent._getTargetNode().removeChild(this.getElement());

        // After Remove DOM Event
        this._afterRemoveDom();
      }

      // Remove from parents children queue
      vParent._removeChildFromChildrenQueue(this);

      if (this.getVisibility()) {
        this._afterDisappear();
      }
    }
  }

  this._handleDisplayableCustom(vDisplayable, vParent, vHint);

  return true;
}

qx.Proto.addToCustomQueues = qx.util.Return.returnTrue;
qx.Proto.removeFromCustomQueues = qx.util.Return.returnTrue;

qx.Proto._handleDisplayableCustom = qx.util.Return.returnTrue;

qx.Proto._computeDisplayable = function() {
  return this.getDisplay() && this._hasParent && this.getParent()._isDisplayable ? true : false;
}

qx.Proto._beforeAppear = function()
{
  // this.debug("_beforeAppear");
  this.createDispatchEvent("beforeAppear");
}

qx.Proto._afterAppear = function()
{
  // this.debug("_afterAppear");
  this._isSeeable = true;
  this.createDispatchEvent("appear");
}

qx.Proto._beforeDisappear = function()
{
  // this.debug("_beforeDisappear");

  // Remove any hover/pressed styles
  this.removeState("over");

  if (qx.OO.isAvailable("qx.ui.form.Button"))
  {
    this.removeState("pressed");
    this.removeState("abandoned");
  }

  // this.debug("_beforeDisappear");
  this.createDispatchEvent("beforeDisappear");
}

qx.Proto._afterDisappear = function()
{
  // this.debug("_afterDisappear");
  this._isSeeable = false;
  this.createDispatchEvent("disappear");
}

qx.Proto._isSeeable = false;

/**
 * If the widget is currently seeable which means that it:
 *
 *   * has a also seeable parent
 *   * visibility is true
 *   * display is true
 */
qx.Proto.isSeeable = function() {
  return this._isSeeable;
}

qx.Proto.isAppearRelevant = function() {
  return this.getVisibility() && this._isDisplayable;
}





/*
---------------------------------------------------------------------------
  DOM SIGNAL HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._beforeInsertDom = function()
{
  // this.debug("_beforeInsertDom");
  this.createDispatchEvent("beforeInsertDom");
}

qx.Proto._afterInsertDom = function()
{
  // this.debug("_afterInsertDom");
  this.createDispatchEvent("insertDom");
}

qx.Proto._beforeRemoveDom = function()
{
  // this.debug("_beforeRemoveDom");
  this.createDispatchEvent("beforeRemoveDom");
}

qx.Proto._afterRemoveDom = function()
{
  // this.debug("_afterRemoveDom");
  this.createDispatchEvent("removeDom");
}






/*
---------------------------------------------------------------------------
  VISIBILITY HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._modifyVisibility = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    if (this._isDisplayable) {
      this._beforeAppear();
    }

    this.removeStyleProperty("display");

    if (this._isDisplayable) {
      this._afterAppear();
    }
  }
  else
  {
    if (this._isDisplayable) {
      this._beforeDisappear();
    }

    this.setStyleProperty("display", "none");

    if (this._isDisplayable) {
      this._afterDisappear();
    }
  }

  return true;
}

qx.Proto.show = function()
{
  this.setVisibility(true);
  this.setDisplay(true);
}

qx.Proto.hide = function() {
  this.setVisibility(false);
}

qx.Proto.connect = function() {
  this.setDisplay(true);
}

qx.Proto.disconnect = function() {
  this.setDisplay(false);
}





/*
---------------------------------------------------------------------------
  ENHANCED BORDER SUPPORT
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._createElementForEnhancedBorder = qx.util.Return.returnTrue;
}
else
{
  qx.Proto._createElementForEnhancedBorder = function()
  {
    // Enhanced Border Test (for IE and Opera)
    if (qx.renderer.border.Border.enhancedCrossBrowserMode &&
        this.getTagName() == "div" &&
        !this._borderElement)
    {
      var el = this.getElement();
      var cl = this._borderElement = document.createElement("div");

      var es = el.style;
      var cs = this._borderStyle = cl.style;

      cs.width = cs.height = "100%";
      cs.position = "absolute";

      for (var i in this._styleProperties)
      {
        switch(i)
        {
          case "position":
          case "zIndex":
          case "filter":
          case "display":
            break;

          default:
            cs[i] = this._styleProperties[i];
            es[i] = "";
        }
      }

      // Move existing children
      while(el.firstChild) {
        cl.appendChild(el.firstChild);
      }

      el.appendChild(cl);
    }
  }
}







/*
---------------------------------------------------------------------------
  DOM ELEMENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._isCreated = false;

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._getTargetNode = function() {
    return this._element;
  }
}
else
{
  qx.Proto._getTargetNode = function() {
    return this._borderElement || this._element;
  }
}

qx.Proto.addToDocument = function() {
  qx.ui.core.ClientDocument.getInstance().add(this);
}

/*!
  Check if the widget is created (or the element is already available).
*/
qx.Proto.isCreated = function() {
  return this._isCreated;
}

/*!
  Create widget with empty element (of specified tagname).
*/
qx.Proto._createElementImpl = function() {
  this.setElement(this.getTopLevelWidget().getDocumentElement().createElement(this.getTagName()));
}

qx.Proto._modifyElement = function(propValue, propOldValue, propData)
{
  this._isCreated = qx.util.Validation.isValidElement(propValue);

  if (propOldValue)
  {
    // reset reference to widget instance
    propOldValue.qx_Widget = null;

    // remove events
    this._removeInlineEvents(propOldValue);
  }

  if (propValue)
  {
    // add reference to widget instance
    propValue.qx_Widget = this;

    // link element and style reference
    this._element = propValue;
    this._style = propValue.style;

    this._applyStyleProperties(propValue);
    this._applyHtmlProperties(propValue);
    this._applyHtmlAttributes(propValue);
    this._applyElementData(propValue);

    // attach inline events
    this._addInlineEvents(propValue);

    // send out create event
    this.createDispatchEvent("create");
  }
  else
  {
    this._element = this._style = null;
  }

  return true;
}







/*
---------------------------------------------------------------------------
  JOBS QUEUE
---------------------------------------------------------------------------
*/

qx.Proto.addToJobQueue = function(p)
{
  if (this._hasParent) {
    qx.ui.core.Widget.addToGlobalJobQueue(this);
  }

  if (!this._jobQueue) {
    this._jobQueue = {};
  }

  this._jobQueue[p] = true;
  return true;
}

qx.Proto._flushJobQueue = function(q)
{
  /* --------------------------------------------------------------------------------
       1. Pre checks
  -------------------------------------------------------------------------------- */

  try
  {
    var vQueue = this._jobQueue;
    var vParent = this.getParent();

    if (!vParent || qx.lang.Object.isEmpty(vQueue)) {
      return;
    }

    var vLayoutImpl = this instanceof qx.ui.core.Parent ? this.getLayoutImpl() : null;

    if (vLayoutImpl) {
      vLayoutImpl.updateSelfOnJobQueueFlush(vQueue);
    }
  }
  catch(ex)
  {
    this.error("Flushing job queue (prechecks#1) failed", ex);
  }





  /* --------------------------------------------------------------------------------
       2. Recompute dimensions
  -------------------------------------------------------------------------------- */

  try
  {
    var vFlushParentJobQueue = false;
    var vRecomputeOuterWidth = vQueue.marginLeft || vQueue.marginRight;
    var vRecomputeOuterHeight = vQueue.marginTop || vQueue.marginBottom;
    var vRecomputeInnerWidth = vQueue.frameWidth;
    var vRecomputeInnerHeight = vQueue.frameHeight;
    var vRecomputeParentPreferredInnerWidth = (vQueue.frameWidth || vQueue.preferredInnerWidth) && this._recomputePreferredBoxWidth();
    var vRecomputeParentPreferredInnerHeight = (vQueue.frameHeight || vQueue.preferredInnerHeight) && this._recomputePreferredBoxHeight();

    if (vRecomputeParentPreferredInnerWidth)
    {
      var vPref = this.getPreferredBoxWidth();

      if (this._computedWidthTypeAuto)
      {
        this._computedWidthValue = vPref;
        vQueue.width = true;
      }

      if (this._computedMinWidthTypeAuto)
      {
        this._computedMinWidthValue = vPref;
        vQueue.minWidth = true;
      }

      if (this._computedMaxWidthTypeAuto)
      {
        this._computedMaxWidthValue = vPref;
        vQueue.maxWidth = true;
      }
    }

    if (vRecomputeParentPreferredInnerHeight)
    {
      var vPref = this.getPreferredBoxHeight();

      if (this._computedHeightTypeAuto)
      {
        this._computedHeightValue = vPref;
        vQueue.height = true;
      }

      if (this._computedMinHeightTypeAuto)
      {
        this._computedMinHeightValue = vPref;
        vQueue.minHeight = true;
      }

      if (this._computedMaxHeightTypeAuto)
      {
        this._computedMaxHeightValue = vPref;
        vQueue.maxHeight = true;
      }
    }

    if ((vQueue.width || vQueue.minWidth || vQueue.maxWidth || vQueue.left || vQueue.right) && this._recomputeBoxWidth()) {
      vRecomputeOuterWidth = vRecomputeInnerWidth = true;
    }

    if ((vQueue.height || vQueue.minHeight || vQueue.maxHeight || vQueue.top || vQueue.bottom) && this._recomputeBoxHeight()) {
      vRecomputeOuterHeight = vRecomputeInnerHeight = true;
    }
  }
  catch(ex)
  {
    this.error("Flushing job queue (recompute#2) failed", ex);
  }





  /* --------------------------------------------------------------------------------
       3. Signals to parent widgets
  -------------------------------------------------------------------------------- */

  try
  {
    if ((vRecomputeOuterWidth && this._recomputeOuterWidth()) ||
        vRecomputeParentPreferredInnerWidth)
    {
      vParent._invalidatePreferredInnerWidth();
      vParent.getLayoutImpl().updateSelfOnChildOuterWidthChange(this);

      vFlushParentJobQueue = true;
    }

    if ((vRecomputeOuterHeight && this._recomputeOuterHeight()) ||
        vRecomputeParentPreferredInnerHeight)
    {
      vParent._invalidatePreferredInnerHeight();
      vParent.getLayoutImpl().updateSelfOnChildOuterHeightChange(this);

      vFlushParentJobQueue = true;
    }

    if (vFlushParentJobQueue) {
      vParent._flushJobQueue();
    }
  }
  catch(ex)
  {
    this.error("Flushing job queue (parentsignals#3) failed", ex);
  }





  /* --------------------------------------------------------------------------------
       4. Add layout jobs
  -------------------------------------------------------------------------------- */

  try
  {
    // add to layout queue
    vParent._addChildToChildrenQueue(this);

    // convert jobs to layout jobs
    for (var i in vQueue) {
      this._layoutChanges[i] = true;
    }
  }
  catch(ex)
  {
    this.error("Flushing job queue (addjobs#4) failed", ex);
  }





  /* --------------------------------------------------------------------------------
       5. Signals to children
  -------------------------------------------------------------------------------- */

  try
  {
    // inform children about padding change
    if (this instanceof qx.ui.core.Parent &&
        (vQueue.paddingLeft ||
         vQueue.paddingRight ||
         vQueue.paddingTop ||
         vQueue.paddingBottom))
    {
      var ch=this.getChildren(), chl=ch.length;

      if (vQueue.paddingLeft) {
        for (var i=0; i<chl; i++) {
          ch[i].addToLayoutChanges("parentPaddingLeft");
        }
      }

      if (vQueue.paddingRight) {
        for (var i=0; i<chl; i++) {
          ch[i].addToLayoutChanges("parentPaddingRight");
        }
      }

      if (vQueue.paddingTop) {
        for (var i=0; i<chl; i++) {
          ch[i].addToLayoutChanges("parentPaddingTop");
        }
      }

      if (vQueue.paddingBottom) {
        for (var i=0; i<chl; i++) {
          ch[i].addToLayoutChanges("parentPaddingBottom");
        }
      }
    }

    if (vRecomputeInnerWidth) {
      this._recomputeInnerWidth();
    }

    if (vRecomputeInnerHeight) {
      this._recomputeInnerHeight();
    }

    if (this._initialLayoutDone)
    {
      if (vLayoutImpl) {
        vLayoutImpl.updateChildrenOnJobQueueFlush(vQueue);
      }
    }
  }
  catch(ex)
  {
    this.error("Flushing job queue (childrensignals#5) failed", ex);
  }



  /* --------------------------------------------------------------------------------
       5. Cleanup
  -------------------------------------------------------------------------------- */

  delete this._jobQueue;
}





/*
---------------------------------------------------------------------------
  METHODS TO GIVE THE LAYOUTERS INFORMATION
---------------------------------------------------------------------------
*/

qx.Proto._isWidthEssential = qx.util.Return.returnTrue;
qx.Proto._isHeightEssential = qx.util.Return.returnTrue;







/*
---------------------------------------------------------------------------
  APPLY LAYOUT STYLES
---------------------------------------------------------------------------
*/

qx.ui.core.Widget.initApplyMethods = function()
{
  var f = "_applyRuntime";
  var r = "_resetRuntime";
  var s = "this._style.";
  var e = "=''";
  var v = "=v+'px'";
  var vpar = "v";

  var props = ["left", "right", "top", "bottom", "width", "height",
               "minWidth", "maxWidth", "minHeight", "maxHeight"];
  var propsup = ["Left", "Right", "Top", "Bottom", "Width", "Height",
                 "MinWidth", "MaxWidth", "MinHeight", "MaxHeight"];

  for (var i=0, fn=f+"Margin", rn=r+"Margin", sp=s+"margin"; i<4; i++)
  {
    qx.Proto[fn+propsup[i]] = new Function(vpar, sp + propsup[i] + v);
    qx.Proto[rn+propsup[i]] = new Function(sp + propsup[i] + e);
  }

  var pad = "padding";
  var upad = "Padding";

  if (qx.sys.Client.getInstance().isGecko())
  {
    for (var i=0, fn=f+upad, rn=r+upad, sp=s+pad; i<4; i++)
    {
      qx.Proto[fn+propsup[i]] = new Function(vpar, sp + propsup[i] + v);
      qx.Proto[rn+propsup[i]] = new Function(sp + propsup[i] + e);
    }
  }
  else
  {
    // need to use setStyleProperty to keep compatibility with enhanced cross browser borders
    var s1="this.setStyleProperty('padding";
    var s2="', v+'px')";
    var s3="this.removeStyleProperty('padding";
    var s4="')";

    for (var i=0, fn=f+upad, rn=r+upad, sp=s+pad; i<4; i++)
    {
      qx.Proto[fn+propsup[i]] = new Function(vpar, s1 + propsup[i] + s2);
      qx.Proto[rn+propsup[i]] = new Function(s3 + propsup[i] + s4);
    }
  }

  /*
    Use optimized method for internet explorer
    to omit string concat and directly setup
    the new layout property.

    We could not use this to reset the value however.
    It seems that is just doesn't work this way. And the
    left/top always get priority. Tried: "", null, "auto".
    Nothing helps.

    Now I've switched back to the conventional method
    to reset the value. This seems to work again.
  */
  if (qx.sys.Client.getInstance().isMshtml())
  {
    for (var i=0, tpos="pos", vset="=v"; i<6; i++)
    {
      // to debug the values which will be applied use this instead of the
      // first line:
      // qx.Proto[f+propsup[i]] = new Function(vpar, "this.debug('v: ' + v); " + s + tpos + propsup[i] + vset);

      qx.Proto[f+propsup[i]] = new Function(vpar, s + tpos + propsup[i] + vset);
      qx.Proto[r+propsup[i]] = new Function(s + props[i] + e);
    }
  }
  else
  {
    for (var i=0; i<10; i++)
    {
      // to debug the values which will be applied use this instead of the
      // first line:
      // qx.Proto[f+propsup[i]] = new Function(vpar, "this.debug('v: ' + v); " + s + props[i] + v);

      qx.Proto[f+propsup[i]] = new Function(vpar, s + props[i] + v);
      qx.Proto[r+propsup[i]] = new Function(s + props[i] + e);
    }
  }
}

qx.ui.core.Widget.initApplyMethods();






/*
---------------------------------------------------------------------------
  DIMENSION CACHE
---------------------------------------------------------------------------
*/

/*
  Add basic setter/getters
*/

qx.OO.addCachedProperty({ name : "innerWidth", defaultValue : null });
qx.OO.addCachedProperty({ name : "innerHeight", defaultValue : null });
qx.OO.addCachedProperty({ name : "boxWidth", defaultValue : null });
qx.OO.addCachedProperty({ name : "boxHeight", defaultValue : null });
qx.OO.addCachedProperty({ name : "outerWidth", defaultValue : null });
qx.OO.addCachedProperty({ name : "outerHeight", defaultValue : null });

qx.Proto._computeBoxWidthFallback = function() {
  return 0;
}

qx.Proto._computeBoxHeightFallback = function() {
  return 0;
}

qx.Proto._computeBoxWidth = function() {
  var vLayoutImpl = this.getParent().getLayoutImpl();
  return Math.max(0,
                  qx.lang.Number.limit(vLayoutImpl.computeChildBoxWidth(this),
                                       this.getMinWidthValue(),
                                       this.getMaxWidthValue()));
}

qx.Proto._computeBoxHeight = function() {
  var vLayoutImpl = this.getParent().getLayoutImpl();
  return Math.max(0,
                  qx.lang.Number.limit(vLayoutImpl.computeChildBoxHeight(this),
                                       this.getMinHeightValue(),
                                       this.getMaxHeightValue()));
}

qx.Proto._computeOuterWidth = function() {
  return Math.max(0,
                  (this.getMarginLeft() +
                   this.getBoxWidth() +
                   this.getMarginRight()));
}

qx.Proto._computeOuterHeight = function() {
  return Math.max(0,
                  (this.getMarginTop() +
                   this.getBoxHeight() +
                   this.getMarginBottom()));
}

qx.Proto._computeInnerWidth = function() {
  return Math.max(0, this.getBoxWidth() - this.getFrameWidth());
}

qx.Proto._computeInnerHeight = function() {
  return Math.max(0, this.getBoxHeight() - this.getFrameHeight());
}

qx.Proto.getNeededWidth = function() {
  var vLayoutImpl = this.getParent().getLayoutImpl();
  return Math.max(0, vLayoutImpl.computeChildNeededWidth(this));
}

qx.Proto.getNeededHeight = function() {
  var vLayoutImpl = this.getParent().getLayoutImpl();
  return Math.max(0, vLayoutImpl.computeChildNeededHeight(this));
}







/*
---------------------------------------------------------------------------
  RECOMPUTE FLEX VALUES
---------------------------------------------------------------------------
*/

qx.Proto._recomputeFlexX = function()
{
  if (!this.getHasFlexX()) {
    return false;
  }

  if (this._computedWidthTypeFlex)
  {
    this._computedWidthValue = null;
    this.addToLayoutChanges("width");
  }

  return true;
}

qx.Proto._recomputeFlexY = function()
{
  if (!this.getHasFlexY()) {
    return false;
  }

  if (this._computedHeightTypeFlex)
  {
    this._computedHeightValue = null;
    this.addToLayoutChanges("height");
  }

  return true;
}







/*
---------------------------------------------------------------------------
  RECOMPUTE PERCENTS
---------------------------------------------------------------------------
*/

qx.Proto._recomputePercentX = function()
{
  if (!this.getHasPercentX()) {
    return false;
  }

  if (this._computedWidthTypePercent)
  {
    this._computedWidthValue = null;
    this.addToLayoutChanges("width");
  }

  if (this._computedMinWidthTypePercent)
  {
    this._computedMinWidthValue = null;
    this.addToLayoutChanges("minWidth");
  }

  if (this._computedMaxWidthTypePercent)
  {
    this._computedMaxWidthValue = null;
    this.addToLayoutChanges("maxWidth");
  }

  if (this._computedLeftTypePercent)
  {
    this._computedLeftValue = null;
    this.addToLayoutChanges("left");
  }

  if (this._computedRightTypePercent)
  {
    this._computedRightValue = null;
    this.addToLayoutChanges("right");
  }

  return true;
}

qx.Proto._recomputePercentY = function()
{
  if (!this.getHasPercentY()) {
    return false;
  }

  if (this._computedHeightTypePercent)
  {
    this._computedHeightValue = null;
    this.addToLayoutChanges("height");
  }

  if (this._computedMinHeightTypePercent)
  {
    this._computedMinHeightValue = null;
    this.addToLayoutChanges("minHeight");
  }

  if (this._computedMaxHeightTypePercent)
  {
    this._computedMaxHeightValue = null;
    this.addToLayoutChanges("maxHeight");
  }

  if (this._computedTopTypePercent)
  {
    this._computedTopValue = null;
    this.addToLayoutChanges("top");
  }

  if (this._computedBottomTypePercent)
  {
    this._computedBottomValue = null;
    this.addToLayoutChanges("bottom");
  }

  return true;
}







/*
---------------------------------------------------------------------------
  RECOMPUTE RANGES
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml() || qx.sys.Client.getInstance().isOpera())
{
  qx.Proto._recomputeRangeX = function()
  {
    if (this._computedLeftTypeNull || this._computedRightTypeNull) {
      return false;
    }

    this.addToLayoutChanges("width");
    return true;
  }

  qx.Proto._recomputeRangeY = function()
  {
    if (this._computedTopTypeNull || this._computedBottomTypeNull) {
      return false;
    }

    this.addToLayoutChanges("height");
    return true;
  }
}
else
{
  qx.Proto._recomputeRangeX = function() {
    return !(this._computedLeftTypeNull || this._computedRightTypeNull);
  }

  qx.Proto._recomputeRangeY = function() {
    return !(this._computedTopTypeNull || this._computedBottomTypeNull);
  }
}






/*
---------------------------------------------------------------------------
  RECOMPUTE STRETCHING
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml() || qx.sys.Client.getInstance().isOpera())
{
  qx.Proto._recomputeStretchingX = function()
  {
    if (this.getAllowStretchX() && this._computedWidthTypeNull)
    {
      this._computedWidthValue = null;
      this.addToLayoutChanges("width");

      return true;
    }

    return false;
  }

  qx.Proto._recomputeStretchingY = function()
  {
    if (this.getAllowStretchY() && this._computedHeightTypeNull)
    {
      this._computedHeightValue = null;
      this.addToLayoutChanges("height");

      return true;
    }

    return false;
  }
}
else
{
  qx.Proto._recomputeStretchingX = function()
  {
    if (this.getAllowStretchX() && this._computedWidthTypeNull) {
      return true;
    }

    return false;
  }

  qx.Proto._recomputeStretchingY = function()
  {
    if (this.getAllowStretchY() && this._computedHeightTypeNull) {
      return true;
    }

    return false;
  }
}






/*
---------------------------------------------------------------------------
  INTELLIGENT GETTERS FOR STANDALONE DIMENSIONS: HELPERS
---------------------------------------------------------------------------
*/

qx.Proto._computeValuePixel = function(v) {
  return Math.round(v);
}

qx.Proto._computeValuePixelLimit = function(v) {
  return Math.max(0, this._computeValuePixel(v));
}

qx.Proto._computeValuePercentX = function(v) {
  return Math.round(this.getParent().getInnerWidthForChild(this) * v * 0.01);
}

qx.Proto._computeValuePercentXLimit = function(v) {
  return Math.max(0, this._computeValuePercentX(v));
}

qx.Proto._computeValuePercentY = function(v) {
  return Math.round(this.getParent().getInnerHeightForChild(this) * v * 0.01);
}

qx.Proto._computeValuePercentYLimit = function(v) {
  return Math.max(0, this._computeValuePercentY(v));
}





/*
---------------------------------------------------------------------------
  INTELLIGENT GETTERS FOR STANDALONE DIMENSIONS: X-AXIS
---------------------------------------------------------------------------
*/

qx.Proto.getWidthValue = function()
{
  if (this._computedWidthValue != null) {
    return this._computedWidthValue;
  }

  switch(this._computedWidthType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedWidthValue = this._computeValuePixelLimit(this._computedWidthParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedWidthValue = this._computeValuePercentXLimit(this._computedWidthParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedWidthValue = this.getPreferredBoxWidth();

    case qx.ui.core.Widget.TYPE_FLEX:
      try{
         this.getParent().getLayoutImpl().computeChildrenFlexWidth();
      } catch (e){
        if (this.getParent().getLayoutImpl()["computeChildrenFlexWidth"] == null){
          throw new Error("Widget " + this + ": having flex size but parent layout does not support it");
        } else {
          throw e;
        }
      }
      return this._computedWidthValue = this._computedWidthFlexValue;
  }

  return null;
}

qx.Proto.getMinWidthValue = function()
{
  if (this._computedMinWidthValue != null) {
    return this._computedMinWidthValue;
  }

  switch(this._computedMinWidthType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedWidthValue = this._computeValuePixelLimit(this._computedMinWidthParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedWidthValue = this._computeValuePercentXLimit(this._computedMinWidthParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedMinWidthValue = this.getPreferredBoxWidth();
  }

  return null;
}

qx.Proto.getMaxWidthValue = function()
{
  if (this._computedMaxWidthValue != null) {
    return this._computedMaxWidthValue;
  }

  switch(this._computedMaxWidthType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedWidthValue = this._computeValuePixelLimit(this._computedMaxWidthParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedWidthValue = this._computeValuePercentXLimit(this._computedMaxWidthParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedMaxWidthValue = this.getPreferredBoxWidth();
  }

  return null;
}

qx.Proto.getLeftValue = function()
{
  if (this._computedLeftValue != null) {
    return this._computedLeftValue;
  }

  switch(this._computedLeftType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedLeftValue = this._computeValuePixel(this._computedLeftParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedLeftValue = this._computeValuePercentX(this._computedLeftParsed);
  }

  return null;
}

qx.Proto.getRightValue = function()
{
  if (this._computedRightValue != null) {
    return this._computedRightValue;
  }

  switch(this._computedRightType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedRightValue = this._computeValuePixel(this._computedRightParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedRightValue = this._computeValuePercentX(this._computedRightParsed);
  }

  return null;
}







/*
---------------------------------------------------------------------------
  INTELLIGENT GETTERS FOR STANDALONE DIMENSIONS: Y-AXIS
---------------------------------------------------------------------------
*/

qx.Proto.getHeightValue = function()
{
  if (this._computedHeightValue != null) {
    return this._computedHeightValue;
  }

  switch(this._computedHeightType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedHeightValue = this._computeValuePixelLimit(this._computedHeightParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedHeightValue = this._computeValuePercentYLimit(this._computedHeightParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedHeightValue = this.getPreferredBoxHeight();

    case qx.ui.core.Widget.TYPE_FLEX:
      try{
        this.getParent().getLayoutImpl().computeChildrenFlexHeight();
      } catch (e){
        if (this.getParent().getLayoutImpl()["computeChildrenFlexHeight"] == null){
          throw new Error("Widget " + this + ": having flex size but parent layout does not support it");
        } else {
          throw e;
        }
      }
      return this._computedHeightValue = this._computedHeightFlexValue;
  }

  return null;
}

qx.Proto.getMinHeightValue = function()
{
  if (this._computedMinHeightValue != null) {
    return this._computedMinHeightValue;
  }

  switch(this._computedMinHeightType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedMinHeightValue = this._computeValuePixelLimit(this._computedMinHeightParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedMinHeightValue = this._computeValuePercentYLimit(this._computedMinHeightParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedMinHeightValue = this.getPreferredBoxHeight();
  }

  return null;
}

qx.Proto.getMaxHeightValue = function()
{
  if (this._computedMaxHeightValue != null) {
    return this._computedMaxHeightValue;
  }

  switch(this._computedMaxHeightType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedMaxHeightValue = this._computeValuePixelLimit(this._computedMaxHeightParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedMaxHeightValue = this._computeValuePercentYLimit(this._computedMaxHeightParsed);

    case qx.ui.core.Widget.TYPE_AUTO:
      return this._computedMaxHeightValue = this.getPreferredBoxHeight();
  }

  return null;
}

qx.Proto.getTopValue = function()
{
  if (this._computedTopValue != null) {
    return this._computedTopValue;
  }

  switch(this._computedTopType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedTopValue = this._computeValuePixel(this._computedTopParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedTopValue = this._computeValuePercentY(this._computedTopParsed);
  }

  return null;
}

qx.Proto.getBottomValue = function()
{
  if (this._computedBottomValue != null) {
    return this._computedBottomValue;
  }

  switch(this._computedBottomType)
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      return this._computedBottomValue = this._computeValuePixel(this._computedBottomParsed);

    case qx.ui.core.Widget.TYPE_PERCENT:
      return this._computedBottomValue = this._computeValuePercentY(this._computedBottomParsed);
  }

  return null;
}









/*
---------------------------------------------------------------------------
  FRAME DIMENSIONS
---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "frameWidth", defaultValue : null, addToQueueRuntime : true });
qx.OO.addCachedProperty({ name : "frameHeight", defaultValue : null, addToQueueRuntime : true });

qx.Proto._computeFrameWidth = function()
{
  var fw = this._cachedBorderLeft + this.getPaddingLeft() + this.getPaddingRight() + this._cachedBorderRight;

  switch(this.getOverflow())
  {
    case "scroll":
    case "scrollY":
      qx.ui.core.Widget.initOverflow();
      fw += qx.ui.core.Widget.SCROLLBAR_SIZE;
      break;

    case "auto":
      // This seems to be really hard to implement
      // this.debug("Check Auto Scroll-X: " + this.getPreferredBoxHeight() + " :: " + this.getBoxHeight());
      break;
  }

  return fw;
}

qx.Proto._computeFrameHeight = function()
{
  var fh = this._cachedBorderTop + this.getPaddingTop() + this.getPaddingBottom() + this._cachedBorderBottom;

  switch(this.getOverflow())
  {
    case "scroll":
    case "scrollX":
      qx.ui.core.Widget.initOverflow();
      fh += qx.ui.core.Widget.SCROLLBAR_SIZE;
      break;

    case "auto":
      // This seems to be really hard to implement
      // this.debug("Check Auto Scroll-Y: " + this.getPreferredBoxWidth() + " :: " + this.getBoxWidth());
      break;
  }

  return fh;
}

qx.Proto._invalidateFrameDimensions = function()
{
  this._invalidateFrameWidth();
  this._invalidateFrameHeight();
}







/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS: INNER
---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "preferredInnerWidth", defaultValue : null, addToQueueRuntime : true });
qx.OO.addCachedProperty({ name : "preferredInnerHeight", defaultValue : null, addToQueueRuntime : true });

qx.Proto._invalidatePreferredInnerDimensions = function()
{
  this._invalidatePreferredInnerWidth();
  this._invalidatePreferredInnerHeight();
}







/*
---------------------------------------------------------------------------
  PREFERRED DIMENSIONS: BOX
---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "preferredBoxWidth", defaultValue : null });
qx.OO.addCachedProperty({ name : "preferredBoxHeight", defaultValue : null });

qx.Proto._computePreferredBoxWidth = function()
{
  try {
    return Math.max(0, this.getPreferredInnerWidth() + this.getFrameWidth());
  } catch(ex) {
    this.error("_computePreferredBoxWidth failed", ex);
  }
}

qx.Proto._computePreferredBoxHeight = function()
{
  try {
    return Math.max(0, this.getPreferredInnerHeight() + this.getFrameHeight());
  } catch(ex) {
    this.error("_computePreferredBoxHeight failed", ex);
  }
}







/*
---------------------------------------------------------------------------
  LAYOUT QUEUE
---------------------------------------------------------------------------
*/

qx.Proto._initialLayoutDone = false;

qx.Proto.addToLayoutChanges = function(p)
{
  if (this._isDisplayable) {
    this.getParent()._addChildToChildrenQueue(this);
  }

  return this._layoutChanges[p] = true;
}

qx.Proto.addToQueue = function(p) {
  this._initialLayoutDone ? this.addToJobQueue(p) : this.addToLayoutChanges(p);
}

qx.Proto.addToQueueRuntime = function(p) {
  return !this._initialLayoutDone || this.addToJobQueue(p);
}







/*
---------------------------------------------------------------------------
  BORDER/MARGIN/PADDING
---------------------------------------------------------------------------
*/

qx.Proto._applyBorderX = function(vChild, vChanges, vStyle)
{
  var vBorder = vChild.getBorder();
  vBorder ? vBorder._applyWidgetX(vChild) : qx.renderer.border.Border._resetBorderX(vChild);
}

qx.Proto._applyBorderY = function(vChild, vChanges, vStyle)
{
  var vBorder = vChild.getBorder();
  vBorder ? vBorder._applyWidgetY(vChild) : qx.renderer.border.Border._resetBorderY(vChild);
}

qx.Proto._applyPaddingX = qx.util.Return.returnTrue;
qx.Proto._applyPaddingY = qx.util.Return.returnTrue;










/*
---------------------------------------------------------------------------
  LAYOUT AUTO/PERCENT CACHE
---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "hasPercentX", defaultValue : false });
qx.OO.addCachedProperty({ name : "hasPercentY", defaultValue : false });
qx.OO.addCachedProperty({ name : "hasAutoX", defaultValue : false });
qx.OO.addCachedProperty({ name : "hasAutoY", defaultValue : false });
qx.OO.addCachedProperty({ name : "hasFlexX", defaultValue : false });
qx.OO.addCachedProperty({ name : "hasFlexY", defaultValue : false });

qx.Proto._computeHasPercentX = function() {
  return (this._computedLeftTypePercent ||
          this._computedWidthTypePercent ||
          this._computedMinWidthTypePercent ||
          this._computedMaxWidthTypePercent ||
          this._computedRightTypePercent);
}

qx.Proto._computeHasPercentY = function() {
  return (this._computedTopTypePercent ||
          this._computedHeightTypePercent ||
          this._computedMinHeightTypePercent ||
          this._computedMaxHeightTypePercent ||
          this._computedBottomTypePercent);
}

qx.Proto._computeHasAutoX = function() {
  return (this._computedWidthTypeAuto ||
          this._computedMinWidthTypeAuto ||
          this._computedMaxWidthTypeAuto);
}

qx.Proto._computeHasAutoY = function() {
  return (this._computedHeightTypeAuto ||
          this._computedMinHeightTypeAuto ||
          this._computedMaxHeightTypeAuto);
}

qx.Proto._computeHasFlexX = function() {
  return this._computedWidthTypeFlex;
}

qx.Proto._computeHasFlexY = function() {
  return this._computedHeightTypeFlex;
}







/*
---------------------------------------------------------------------------
  LAYOUT TYPE INDENTIFY HELPER METHODS
---------------------------------------------------------------------------
*/

qx.ui.core.Widget.TYPE_NULL = 0;
qx.ui.core.Widget.TYPE_PIXEL = 1;
qx.ui.core.Widget.TYPE_PERCENT = 2;
qx.ui.core.Widget.TYPE_AUTO = 3;
qx.ui.core.Widget.TYPE_FLEX = 4;

qx.Proto._evalUnitsPixelPercentAutoFlex = function(propValue)
{
  switch(propValue)
  {
    case "auto":
      return qx.ui.core.Widget.TYPE_AUTO;

    case Infinity:
    case -Infinity:
      return qx.ui.core.Widget.TYPE_NULL;
  }

  switch(typeof propValue)
  {
    case "number":
      return isNaN(propValue) ? qx.ui.core.Widget.TYPE_NULL : qx.ui.core.Widget.TYPE_PIXEL;

    case "string":
      return propValue.indexOf("%") != -1 ? qx.ui.core.Widget.TYPE_PERCENT : propValue.indexOf("*") != -1 ? qx.ui.core.Widget.TYPE_FLEX : qx.ui.core.Widget.TYPE_NULL;
  }

  return qx.ui.core.Widget.TYPE_NULL;
}

qx.Proto._evalUnitsPixelPercentAuto = function(propValue)
{
  switch(propValue)
  {
    case "auto":
      return qx.ui.core.Widget.TYPE_AUTO;

    case Infinity:
    case -Infinity:
      return qx.ui.core.Widget.TYPE_NULL;
  }

  switch(typeof propValue)
  {
    case "number":
      return isNaN(propValue) ? qx.ui.core.Widget.TYPE_NULL : qx.ui.core.Widget.TYPE_PIXEL;

    case "string":
      return propValue.indexOf("%") != -1 ? qx.ui.core.Widget.TYPE_PERCENT : qx.ui.core.Widget.TYPE_NULL;
  }

  return qx.ui.core.Widget.TYPE_NULL;
}

qx.Proto._evalUnitsPixelPercent = function(propValue)
{
  switch(propValue)
  {
    case Infinity:
    case -Infinity:
      return qx.ui.core.Widget.TYPE_NULL;
  }

  switch(typeof propValue)
  {
    case "number":
      return isNaN(propValue) ? qx.ui.core.Widget.TYPE_NULL : qx.ui.core.Widget.TYPE_PIXEL;

    case "string":
      return propValue.indexOf("%") != -1 ? qx.ui.core.Widget.TYPE_PERCENT : qx.ui.core.Widget.TYPE_NULL;
  }

  return qx.ui.core.Widget.TYPE_NULL;
}






/*
---------------------------------------------------------------------------
  LAYOUT TYPE AND VALUE KEY PRE-CACHE
---------------------------------------------------------------------------
*/

qx.ui.core.Widget.layoutPropertyTypes = {};

qx.ui.core.Widget.initLayoutProperties = function()
{
  var a = [ "width", "height",
            "minWidth", "maxWidth",
            "minHeight", "maxHeight",
            "left", "right", "top", "bottom" ];

  for (var i=0, l=a.length, p, b, t; i<l; i++)
  {
    p = a[i];
    b = "_computed" + qx.lang.String.toFirstUp(p);
    t = b + "Type";

    qx.ui.core.Widget.layoutPropertyTypes[p] =
    {
      dataType : t,
      dataParsed : b + "Parsed",
      dataValue : b + "Value",

      typePixel : t + "Pixel",
      typePercent : t + "Percent",
      typeAuto : t + "Auto",
      typeFlex : t + "Flex",
      typeNull : t + "Null"
    }
  }
}

qx.ui.core.Widget.initLayoutProperties();





/*
---------------------------------------------------------------------------
  LAYOUT TYPE AND VALUE STORAGE
---------------------------------------------------------------------------
*/

qx.Proto._unitDetectionPixelPercentAutoFlex = function(propData, propValue)
{
  var r = qx.ui.core.Widget.layoutPropertyTypes[propData.name];

  var s = r.dataType;
  var p = r.dataParsed;
  var v = r.dataValue;

  var s1 = r.typePixel;
  var s2 = r.typePercent;
  var s3 = r.typeAuto;
  var s4 = r.typeFlex;
  var s5 = r.typeNull;

  var wasPercent = this[s2];
  var wasAuto = this[s3];
  var wasFlex = this[s4];

  switch(this[s] = this._evalUnitsPixelPercentAutoFlex(propValue))
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      this[s1] = true;
      this[s2] = this[s3] = this[s4] = this[s5] = false;
      this[p] = this[v] = Math.round(propValue);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
      this[s2] = true;
      this[s1] = this[s3] = this[s4] = this[s5] = false;
      this[p] = parseFloat(propValue);
      this[v] = null;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      this[s3] = true;
      this[s1] = this[s2] = this[s4] = this[s5] = false;
      this[p] = this[v] = null;
      break;

    case qx.ui.core.Widget.TYPE_FLEX:
      this[s4] = true;
      this[s1] = this[s2] = this[s3] = this[s5] = false;
      this[p] = parseFloat(propValue);
      this[v] = null;
      break;

    default:
      this[s5] = true;
      this[s1] = this[s2] = this[s3] = this[s4] = false;
      this[p] = this[v] = null;
      break;
  }

  if (wasPercent != this[s2])
  {
    switch(propData.name)
    {
      case "minWidth":
      case "maxWidth":
      case "width":
      case "left":
      case "right":
        this._invalidateHasPercentX();
        break;

      case "maxHeight":
      case "minHeight":
      case "height":
      case "top":
      case "bottom":
        this._invalidateHasPercentY();
        break;
    }
  }

  // No ELSE because you can also switch from percent to auto
  if (wasAuto != this[s3])
  {
    switch(propData.name)
    {
      case "minWidth":
      case "maxWidth":
      case "width":
        this._invalidateHasAutoX();
        break;

      case "minHeight":
      case "maxHeight":
      case "height":
        this._invalidateHasAutoY();
        break;
    }
  }

  // No ELSE because you can also switch from percent to auto
  if (wasFlex != this[s4])
  {
    switch(propData.name)
    {
      case "width":
        this._invalidateHasFlexX();
        break;

      case "height":
        this._invalidateHasFlexY();
        break;
    }
  }
}

qx.Proto._unitDetectionPixelPercentAuto = function(propData, propValue)
{
  var r = qx.ui.core.Widget.layoutPropertyTypes[propData.name];

  var s = r.dataType;
  var p = r.dataParsed;
  var v = r.dataValue;

  var s1 = r.typePixel;
  var s2 = r.typePercent;
  var s3 = r.typeAuto;
  var s4 = r.typeNull;

  var wasPercent = this[s2];
  var wasAuto = this[s3];

  switch(this[s] = this._evalUnitsPixelPercentAuto(propValue))
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      this[s1] = true;
      this[s2] = this[s3] = this[s4] = false;
      this[p] = this[v] = Math.round(propValue);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
      this[s2] = true;
      this[s1] = this[s3] = this[s4] = false;
      this[p] = parseFloat(propValue);
      this[v] = null;
      break;

    case qx.ui.core.Widget.TYPE_AUTO:
      this[s3] = true;
      this[s1] = this[s2] = this[s4] = false;
      this[p] = this[v] = null;
      break;

    default:
      this[s4] = true;
      this[s1] = this[s2] = this[s3] = false;
      this[p] = this[v] = null;
      break;
  }

  if (wasPercent != this[s2])
  {
    switch(propData.name)
    {
      case "minWidth":
      case "maxWidth":
      case "width":
      case "left":
      case "right":
        this._invalidateHasPercentX();
        break;

      case "minHeight":
      case "maxHeight":
      case "height":
      case "top":
      case "bottom":
        this._invalidateHasPercentY();
        break;
    }
  }

  // No ELSE because you can also switch from percent to auto
  if (wasAuto != this[s3])
  {
    switch(propData.name)
    {
      case "minWidth":
      case "maxWidth":
      case "width":
        this._invalidateHasAutoX();
        break;

      case "minHeight":
      case "maxHeight":
      case "height":
        this._invalidateHasAutoY();
        break;
    }
  }
}

qx.Proto._unitDetectionPixelPercent = function(propData, propValue)
{
  var r = qx.ui.core.Widget.layoutPropertyTypes[propData.name];

  var s = r.dataType;
  var p = r.dataParsed;
  var v = r.dataValue;

  var s1 = r.typePixel;
  var s2 = r.typePercent;
  var s3 = r.typeNull;

  var wasPercent = this[s2];

  switch(this[s] = this._evalUnitsPixelPercent(propValue))
  {
    case qx.ui.core.Widget.TYPE_PIXEL:
      this[s1] = true;
      this[s2] = this[s3] = false;
      this[p] = this[v] = Math.round(propValue);
      break;

    case qx.ui.core.Widget.TYPE_PERCENT:
      this[s2] = true;
      this[s1] = this[s3] = false;
      this[p] = parseFloat(propValue);
      this[v] = null;
      break;

    default:
      this[s3] = true;
      this[s1] = this[s2] = false;
      this[p] = this[v] = null;
      break;
  }

  if (wasPercent != this[s2])
  {
    switch(propData.name)
    {
      case "minWidth":
      case "maxWidth":
      case "width":
      case "left":
      case "right":
        this._invalidateHasPercentX();
        break;

      case "minHeight":
      case "maxHeight":
      case "height":
      case "top":
      case "bottom":
        this._invalidateHasPercentY();
        break;
    }
  }
}







/*
---------------------------------------------------------------------------
  INLINE EVENTS
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.ui.core.Widget.inlineEventMap =
  {
    input : "onpropertychange",
    select : "onselect",
    scroll : "onscroll",
    focus : "onfocus",
    blur : "onblur"
  }

  qx.Proto.enableInlineEvent = function(vEventName)
  {
    var vEventType = qx.ui.core.Widget.inlineEventMap[vEventName];

    if (!this._inlineEvents)
    {
      this._inlineEvents = [vEventType];
    }
    else
    {
      this._inlineEvents.push(vEventType);
    }

    if (this._isCreated) {
      this.getElement()[vEventType] = qx.ui.core.Widget.__oninlineevent;
    }
  }

  qx.Proto.disableInlineEvent = function(vEventName)
  {
    var vEventType = qx.ui.core.Widget.inlineEventMap[vEventName];

    if (this._inlineEvents) {
      qx.lang.Array.remove(this._inlineEvents, vEventType);
    }

    if (this._isCreated) {
      this.getElement()[vEventType] = null;
    }
  }

  qx.Proto._addInlineEvents = function(vElement)
  {
    if (this._inlineEvents)
    {
      for (var i=0, a=this._inlineEvents, l=a.length; i<l; i++) {
        vElement[a[i]] = qx.ui.core.Widget.__oninlineevent;
      }
    }
  }

  qx.Proto._removeInlineEvents = function(vElement)
  {
    if (this._inlineEvents)
    {
      for (var i=0, a=this._inlineEvents, l=a.length; i<l; i++) {
        vElement[a[i]] = null;
      }
    }
  }
}
else
{
  qx.Proto.enableInlineEvent = function(vEventName)
  {
    if (!this._inlineEvents)
    {
      this._inlineEvents = [vEventName];
    }
    else
    {
      this._inlineEvents.push(vEventName);
    }

    if (this._isCreated) {
      this.getElement().addEventListener(vEventName, qx.ui.core.Widget.__oninlineevent, false);
    }
  }

  qx.Proto.disableInlineEvent = function(vEventName)
  {
    if (this._inlineEvents) {
      qx.lang.Array.remove(this._inlineEvents, vEventName);
    }

    if (this._isCreated) {
      this.getElement().removeEventListener(vEventName, qx.ui.core.Widget.__oninlineevent, false);
    }
  }

  qx.Proto._addInlineEvents = function(vElement)
  {
    if (this._inlineEvents)
    {
      for (var i=0, a=this._inlineEvents, l=a.length; i<l; i++) {
        vElement.addEventListener(a[i], qx.ui.core.Widget.__oninlineevent, false);
      }
    }
  }

  qx.Proto._removeInlineEvents = function(vElement)
  {
    if (this._inlineEvents)
    {
      for (var i=0, a=this._inlineEvents, l=a.length; i<l; i++) {
        vElement.removeEventListener(a[i], qx.ui.core.Widget.__oninlineevent, false);
      }
    }
  }
}

qx.ui.core.Widget.__oninlineevent = function(e)
{
  if (!e) {
    e = window.event;
  }

  if (this.qx_Widget) {
    return this.qx_Widget._oninlineevent(e);
  }
}

qx.Proto._oninlineevent = function(e)
{
  if (qx.ui.core.Widget._inFlushGlobalQueues) {
    return;
  }

  // this.debug("Inlineevent: " + e.type);

  switch(e.type)
  {
    case "propertychange":
      this._oninlineproperty(e);
      break;

    case "input":
      this._oninlineinput(e);
      break;

    default:
      this.createDispatchEvent(e.type);
  }
}

qx.Proto._oninlineinput = function(e)
{
  this.createDispatchDataEvent("input", this.getComputedValue());

  // Block parents from this event
  if (e.stopPropagation) {
    e.stopPropagation();
  }

  e.returnValue = -1;
}

qx.Proto._oninlineproperty = function(e)
{
  switch(e.propertyName)
  {
    case "value":
      if (!this._inValueProperty) {
        this._oninlineinput(e);
      }

      break;
  }
}







/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT
---------------------------------------------------------------------------
*/

/*!
  The widget which is at the top level,
  which contains all others (normally a
  instance of qx.ui.core.ClientDocument).
*/
qx.Proto.getTopLevelWidget = function() {
  return this._hasParent ? this.getParent().getTopLevelWidget() : null;
}

/*!
  Move myself to immediately before another child of the same parent.
*/
qx.Proto.moveSelfBefore = function(vBefore) {
  this.getParent().addBefore(this, vBefore);
}

/*!
  Move myself to immediately after another child of the same parent.
*/
qx.Proto.moveSelfAfter = function(vAfter) {
  this.getParent().addAfter(this, vAfter);
}

/*!
  Move myself to the head of the list: make me the first child.
*/
qx.Proto.moveSelfToBegin = function() {
  this.getParent().addAtBegin(this);
}

/*!
  Move myself to the end of the list: make me the last child.
*/
qx.Proto.moveSelfToEnd = function() {
  this.getParent().addAtEnd(this);
}

/*!
  Returns the previous sibling.
*/
qx.Proto.getPreviousSibling = function()
{
  var p = this.getParent();

  if(p == null) {
    return null;
  }

  var cs = p.getChildren();
  return cs[cs.indexOf(this) - 1];
}

/*!
  Returns the next sibling.
*/
qx.Proto.getNextSibling = function()
{
  var p = this.getParent();

  if(p == null) {
    return null;
  }

  var cs = p.getChildren();
  return cs[cs.indexOf(this) + 1];
}

/*!
  Returns the previous visible sibling.
*/
qx.Proto.getPreviousVisibleSibling = function()
{
  if(!this._hasParent) {
    return null;
  }

  var vChildren = this.getParent().getVisibleChildren();
  return vChildren[vChildren.indexOf(this) - 1];
}

/*!
  Returns the next visible sibling.
*/
qx.Proto.getNextVisibleSibling = function()
{
  if(!this._hasParent) {
    return null;
  }

  var vChildren = this.getParent().getVisibleChildren();
  return vChildren[vChildren.indexOf(this) + 1];
}

qx.Proto.getPreviousActiveSibling = function(vIgnoreClasses)
{
  var vPrev = qx.ui.core.Widget.getActiveSiblingHelper(this, this.getParent(), -1, vIgnoreClasses, null);
  return vPrev ? vPrev : this.getParent().getLastActiveChild();
}

qx.Proto.getNextActiveSibling = function(vIgnoreClasses)
{
  var vNext = qx.ui.core.Widget.getActiveSiblingHelper(this, this.getParent(), 1, vIgnoreClasses, null);
  return vNext ? vNext : this.getParent().getFirstActiveChild();
}

qx.Proto.isFirstChild = function() {
  return this._hasParent && this.getParent().getFirstChild() == this;
}

qx.Proto.isLastChild = function() {
  return this._hasParent && this.getParent().getLastChild() == this;
}

qx.Proto.isFirstVisibleChild = function() {
  return this._hasParent && this.getParent().getFirstVisibleChild() == this;
}

qx.Proto.isLastVisibleChild = function() {
  return this._hasParent && this.getParent().getLastVisibleChild() == this;
}







/*
---------------------------------------------------------------------------
  ENABLED MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyEnabled = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    this.removeState("disabled");
  }
  else
  {
    this.addState("disabled");

    // Also reset some states to be sure a pressed/hovered button gets reset
    this.removeState("over");

    if (qx.OO.isAvailable("qx.ui.form.Button"))
    {
      this.removeState("abandoned");
      this.removeState("pressed");
    }
  }

  return true;
}





/*
---------------------------------------------------------------------------
  STATE HANDLING
---------------------------------------------------------------------------
*/

/**
 * Returns whether a state is set.
 *
 * @param vState {string} the state to check.
 * @return {boolean} whether the state is set.
 */
qx.Proto.hasState = function(vState) {
  return this._states[vState] ? true : false;
}

/**
 * Sets a state.
 *
 * @param state {string} the state to set.
 */
qx.Proto.addState = function(vState)
{
  if (! this._states[vState]) {
    this._states[vState] = true;

    if (this._hasParent) {
      qx.ui.core.Widget.addToGlobalStateQueue(this);
    }
  }
}

/**
 * Clears a state.
 *
 * @param vState {string} the state to clear.
 */
qx.Proto.removeState = function(vState)
{
  if (this._states[vState]) {
    delete this._states[vState];

    if (this._hasParent) {
      qx.ui.core.Widget.addToGlobalStateQueue(this);
    }
  }
}

/**
 * Sets or clears a state.
 *
 * @param state {string} the state to set or clear.
 * @param enabled {boolean} whether the state should be set.
 *        If false it will be cleared.
 */
qx.Proto.setState = function(state, enabled) {
  if (enabled) {
    this.addState(state);
  } else {
    this.removeState(state);
  }
}







/*
---------------------------------------------------------------------------
  APPEARANCE
---------------------------------------------------------------------------
*/

qx.Proto._applyInitialAppearance = function()
{
  var vAppearance = this.getAppearance();

  if (vAppearance)
  {
    try
    {
      var r = qx.manager.object.AppearanceManager.getInstance().getAppearanceTheme().initialFrom(vAppearance);
      if (r) {
        this.set(r);
      }
    }
    catch(ex)
    {
      this.error("Could not apply initial appearance", ex);
    }
  }
}

qx.Proto._applyStateAppearance = function()
{
  // HACK: Is there a cleaner way to implement this?
  // Maybe not use the appearance for this, but a simple property and event handler combination?
  this._applyStateStyleFocus(this._states);

  var vAppearance = this.getAppearance();

  if (vAppearance)
  {
    try
    {
      var r = qx.manager.object.AppearanceManager.getInstance().getAppearanceTheme().stateFrom(vAppearance, this._states);
      if (r) {
        this.set(r);
      }
    }
    catch(ex)
    {
      this.error("Could not apply state appearance", ex);
    }
  }
}

qx.Proto._resetAppearanceThemeWrapper = function(vNewAppearanceTheme, vOldAppearanceTheme)
{
  var vAppearance = this.getAppearance();

  if (vAppearance)
  {
    var vOldAppearanceThemeObject = qx.manager.object.AppearanceManager.getInstance().getThemeById(vOldAppearanceTheme);
    var vNewAppearanceThemeObject = qx.manager.object.AppearanceManager.getInstance().getThemeById(vNewAppearanceTheme);

    var vOldAppearanceProperties = qx.lang.Object.mergeWith(vOldAppearanceThemeObject.initialFrom(vAppearance), vOldAppearanceThemeObject.stateFrom(vAppearance, this._states));
    var vNewAppearanceProperties = qx.lang.Object.mergeWith(vNewAppearanceThemeObject.initialFrom(vAppearance), vNewAppearanceThemeObject.stateFrom(vAppearance, this._states));

    for (var vProp in vOldAppearanceProperties)
    {
      if (!(vProp in vNewAppearanceProperties)) {
        this[qx.OO.resetter[vProp]]();
      }
    }

    this.set(vNewAppearanceProperties);
  }
}

if (qx.sys.Client.getInstance().isMshtml())
{
  /*
    Mshtml does not support outlines by css
  */
  qx.Proto._applyStateStyleFocus = function(vStates) {}
}
else if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._applyStateStyleFocus = function(vStates)
  {
    if (vStates.focused)
    {
      if (!qx.event.handler.FocusHandler.mouseFocus && !this.getHideFocus())
      {
        this.setStyleProperty("MozOutline", "1px dotted invert");
      }
    }
    else
    {
      this.removeStyleProperty("MozOutline");
    }
  }
}
else
{
  qx.Proto._applyStateStyleFocus = function(vStates)
  {
    if (vStates.focused)
    {
      if (!qx.event.handler.FocusHandler.mouseFocus && !this.getHideFocus())
      {
        this.setStyleProperty("outline", "1px dotted invert");
      }
    }
    else
    {
      this.setStyleProperty("outline", "0px none");
    }
  }
}

qx.Proto.addToStateQueue = function() {
  qx.ui.core.Widget.addToGlobalStateQueue(this);
}

qx.Proto.recursiveAddToStateQueue = function() {
  this.addToStateQueue();
}







/*
---------------------------------------------------------------------------
  APPEARANCE MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyAppearance = function(propValue, propOldValue, propData)
{
  var vAppearanceThemeObject = qx.manager.object.AppearanceManager.getInstance().getAppearanceTheme();

  var vNewAppearanceProperties = vAppearanceThemeObject.initialFrom(propValue);

  if (this.isCreated()) {
    qx.lang.Object.mergeWith(vNewAppearanceProperties, vAppearanceThemeObject.stateFrom(propValue, this._states));
  }

  if (propOldValue)
  {
    var vOldAppearanceProperties = vAppearanceThemeObject.initialFrom(propOldValue);

    if (this.isCreated()) {
      qx.lang.Object.mergeWith(vOldAppearanceProperties, vAppearanceThemeObject.stateFrom(propOldValue, this._states));
    }

    for (var vProp in vOldAppearanceProperties)
    {
      if (!(vProp in vNewAppearanceProperties)) {
        this[qx.OO.resetter[vProp]]();
      }
    }
  }

  this.set(vNewAppearanceProperties);

  return true;
}

qx.Proto._recursiveAppearanceThemeUpdate = function(vNewAppearanceTheme, vOldAppearanceTheme)
{
  try
  {
    this._resetAppearanceThemeWrapper(vNewAppearanceTheme, vOldAppearanceTheme);
  }
  catch(ex)
  {
    this.error("Failed to update appearance theme", ex);
  }
}






/*
---------------------------------------------------------------------------
  ELEMENT DATA
---------------------------------------------------------------------------
*/

/*!
  Placeholder method to add attributes and other content to element node
*/
qx.Proto._applyElementData = function(el) {}






/*
---------------------------------------------------------------------------
  HTML PROPERTIES
---------------------------------------------------------------------------
*/

qx.Proto.setHtmlProperty = function(propName, propValue)
{
  if (!this._htmlProperties) {
    this._htmlProperties = {};
  }

  this._htmlProperties[propName] = propValue;

  if (this._isCreated && this.getElement()[propName] != propValue) {
    this.getElement()[propName] = propValue;
  }

  return true;
}

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto.removeHtmlProperty = function(propName)
  {
    if (!this._htmlProperties) {
      return;
    }

    delete this._htmlProperties[propName];

    if (this._isCreated) {
      this.getElement().removeAttribute(propName);
    }

    return true;
  }
}
else
{
  qx.Proto.removeHtmlProperty = function(propName)
  {
    if (!this._htmlProperties) {
      return;
    }

    delete this._htmlProperties[propName];

    if (this._isCreated)
    {
      this.getElement().removeAttribute(propName);
      delete this.getElement()[propName];
    }

    return true;
  }
}

qx.Proto.getHtmlProperty = function(propName)
{
  if (!this._htmlProperties) {
    return "";
  }

  return this._htmlProperties[propName] || "";
}

qx.Proto._applyHtmlProperties = function(vElement)
{
  var vProperties = this._htmlProperties;

  if (vProperties)
  {
    // this.debug("HTML-Properties: " + qx.lang.Object.getLength(vProperties));

    var propName;

    for (propName in vProperties) {
      vElement[propName] = vProperties[propName];
    }
  }
}






/*
---------------------------------------------------------------------------
  HTML ATTRIBUTES
---------------------------------------------------------------------------
*/

qx.Proto.setHtmlAttribute = function(propName, propValue)
{
  if (!this._htmlAttributes) {
    this._htmlAttributes = {};
  }

  this._htmlAttributes[propName] = propValue;

  if (this._isCreated) {
    this.getElement().setAttribute(propName, propValue);
  }

  return true;
}

qx.Proto.removeHtmlAttribute = function(propName)
{
  if (!this._htmlAttributes) {
    return;
  }

  delete this._htmlAttributes[propName];

  if (this._isCreated) {
    this.getElement().removeAttribute(propName);
  }

  return true;
}

qx.Proto.getHtmlAttribute = function(propName)
{
  if (!this._htmlAttributes) {
    return "";
  }

  return this._htmlAttributes[propName] || "";
}

qx.Proto._applyHtmlAttributes = function(vElement)
{
  var vAttributes = this._htmlAttributes;

  if (vAttributes)
  {
    // this.debug("HTML-Attributes: " + qx.lang.Object.getLength(vAttributes));

    var propName;

    for (propName in vAttributes) {
      vElement.setAttribute(propName, vAttributes[propName]);
    }
  }
}






/*
---------------------------------------------------------------------------
  STYLE PROPERTIES
---------------------------------------------------------------------------
*/

qx.Proto.getStyleProperty = function(propName) {
  return this._styleProperties[propName] || "";
}

qx.Proto.setStyleProperty = function(propName, propValue)
{
  this._styleProperties[propName] = propValue;

  if (this._isCreated)
  {
    /*
      The zIndex and filter properties should always be
      applied on the "real" element node.
    */
    switch(propName)
    {
      case "zIndex":
      case "filter":
      case "display":
      case "visibility":
        var vElement = this.getElement();
        break;

      default:
        var vElement = this._getTargetNode();
    }

    if (vElement) {
      vElement.style[propName] = propValue;
    }
  }

  return true;
}

qx.Proto.removeStyleProperty = function(propName)
{
  delete this._styleProperties[propName];

  if (this._isCreated)
  {
    /*
      The zIndex and filter properties should always be
      applied on the "real" element node.
    */
    switch(propName)
    {
      case "zIndex":
      case "filter":
      case "display":
      case "visibility":
        var vElement = this.getElement();
        break;

      default:
        var vElement = this._getTargetNode();
    }

    if (vElement) {
      vElement.style[propName] = "";
    }
  }

  return true;
}

qx.Proto._applyStyleProperties = function(vElement)
{
  var vProperties = this._styleProperties;
  var propName;

  var vBaseElement = vElement;
  var vTargetElement = this._getTargetNode();

  for (propName in vProperties)
  {
    /*
      The zIndex and filter properties should always be
      applied on the "real" element node.
    */
    switch(propName)
    {
      case "zIndex":
      case "filter":
        vElement = vBaseElement;
        break;

      default:
        vElement = vTargetElement;
    }

    vElement.style[propName] = vProperties[propName];
  }
}








/*
---------------------------------------------------------------------------
  FOCUS HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.isFocusable = function() {
  return this.isEnabled() && this.isSeeable() && this.getTabIndex() >= 0;
}

qx.Proto.isFocusRoot = function() {
  return false;
}

qx.Proto.getFocusRoot = function()
{
  if(this._hasParent) {
    return this.getParent().getFocusRoot();
  }

  return null;
}

qx.Proto.getActiveChild = function()
{
  var vRoot = this.getFocusRoot();
  if (vRoot) {
    return vRoot.getActiveChild();
  }

  return null;
}

qx.Proto._ontabfocus = qx.util.Return.returnTrue;

qx.Proto._modifyFocused = function(propValue, propOldValue, propData)
{
  if (!this.isCreated()) {
    return true;
  }

  var vFocusRoot = this.getFocusRoot();

  // this.debug("Focused: " + propValue);

  if (vFocusRoot)
  {
    // may be undefined if this widget has been removed
    if (propValue)
    {
      vFocusRoot.setFocusedChild(this);
      this._visualizeFocus();
    }
    else
    {
      if (vFocusRoot.getFocusedChild() == this) {
        vFocusRoot.setFocusedChild(null);
      }

      this._visualizeBlur();
    }
  }

  return true;
}

qx.Proto._visualizeBlur = function()
{
  // Force blur, even if mouseFocus is not active because we
  // need to be sure that the previous focus rect gets removed.
  // But this only needs to be done, if there is no new focused element.
  if (this.getEnableElementFocus() && (!this.getFocusRoot().getFocusedChild() || (this.getFocusRoot().getFocusedChild() && this.getFocusRoot().getFocusedChild().getEnableElementFocus())))
  {
    try {
      this.getElement().blur();
    } catch(ex) {};
  }

  this.removeState("focused");
  return true;
}

qx.Proto._visualizeFocus = function()
{
  //this.info("_visualizeFocus: " + qx.event.handler.FocusHandler.mouseFocus);
  if (!qx.event.handler.FocusHandler.mouseFocus && this.getEnableElementFocus())
  {
    try {
      this.getElement().focus();
    } catch(ex) {};
  }

  this.addState("focused");
  return true;
}

qx.Proto.focus = function()
{
  delete qx.event.handler.FocusHandler.mouseFocus;
  this.setFocused(true);
}

qx.Proto.blur = function()
{
  delete qx.event.handler.FocusHandler.mouseFocus;
  this.setFocused(false);
}




/*
---------------------------------------------------------------------------
  CAPTURE
---------------------------------------------------------------------------
*/

qx.Proto._modifyCapture = function(propValue, propOldValue, propData)
{
  var vMgr = qx.event.handler.EventHandler.getInstance();

  if (propOldValue)
  {
    vMgr.setCaptureWidget(null);
  }
  else if (propValue)
  {
    vMgr.setCaptureWidget(this);
  }

  return true;
}





/*
---------------------------------------------------------------------------
  ZINDEX
---------------------------------------------------------------------------
*/

qx.Proto._modifyZIndex = function(propValue, propOldValue, propData) {
  return this.setStyleProperty(propData.name, propValue);
}







/*
---------------------------------------------------------------------------
  TAB INDEX
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifyTabIndex = function(propValue, propOldValue, propData)
  {
    if (propValue < 0 || !this.getEnabled()) {
      this.setHtmlProperty("unselectable",
                           "on");
    } else {
      this.removeHtmlProperty("unselectable");
    }

    this.setHtmlProperty("tabIndex",
                         propValue < 0 ? -1 : 1);

    return true;
  }
}
else if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._modifyTabIndex = function(propValue, propOldValue, propData)
  {
    this.setStyleProperty("MozUserFocus",
                          (propValue < 0
                           ? "ignore"
                           : "normal"));

    // be forward compatible (CSS 3 Draft)
    this.setStyleProperty("userFocus",
                          (propValue < 0
                           ? "ignore"
                           : "normal"));

    return true;
  }
}
else
{
  qx.Proto._modifyTabIndex = function(propValue, propOldValue, propData)
  {
    // CSS 3 Draft
    this.setStyleProperty("userFocus",
                          (propValue < 0
                           ? "ignore"
                           : "normal"));

    // IE Backward Compatible
    if (propValue < 0 || !this.getEnabled()) {
      this.setHtmlProperty("unselectable",
                           "on");
    } else {
      this.removeHtmlProperty("unselectable");
    }

    this.setHtmlProperty("tabIndex",
                         propValue < 0 ? -1 : 1);

    return true;
  }
}






/*
---------------------------------------------------------------------------
  CSS CLASS NAME
---------------------------------------------------------------------------
*/

qx.Proto.setCssClassName = function(propValue) {
  this.setHtmlProperty("className", propValue);
}

qx.Proto.getCssClassName = function() {
  return this.getHtmlProperty("className");
}








/*
---------------------------------------------------------------------------
  WIDGET FROM POINT
---------------------------------------------------------------------------
*/

qx.Proto.getWidgetFromPoint = function(x, y)
{
  var ret = this.getWidgetFromPointHelper(x, y);
  return ret && ret != this ? ret : null;
}

qx.Proto.getWidgetFromPointHelper = function(x, y) {
  return this;
}






/*
---------------------------------------------------------------------------
  CAN SELECT
---------------------------------------------------------------------------
*/

if(qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifySelectable = function(propValue, propOldValue, propData)
  {
    if (propValue)
    {
      return this.removeHtmlProperty("unselectable");
    }
    else
    {
      return this.setHtmlProperty("unselectable", "on");
    }
  }
}
else if(qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._modifySelectable = function(propValue, propOldValue, propData)
  {
    if (propValue)
    {
      this.removeStyleProperty("MozUserSelect");
    }
    else
    {
      this.setStyleProperty("MozUserSelect", "none");
    }

    return true;
  };
}
else if (qx.sys.Client.getInstance().isOpera())
{
  // No known method available for this client
  qx.Proto._modifySelectable = function(propValue, propOldValue, propData) {
    return true;
  }
}
else if (qx.sys.Client.getInstance().isKhtml() || qx.sys.Client.getInstance().isWebkit())
{
  qx.Proto._modifySelectable = function(propValue, propOldValue, propData)
  {
    // Be forward compatible and use both userSelect and KhtmlUserSelect
    if (propValue)
    {
      this.removeStyleProperty("KhtmlUserSelect");
    }
    else
    {
      this.setStyleProperty("KhtmlUserSelect", "none");
    }

    return true;
  };
}
else
{
  qx.Proto._modifySelectable = function(propValue, propOldValue, propData)
  {
    if (propValue)
    {
      return this.removeStyleProperty("userSelect");
    }
    else
    {
      this.setStyleProperty("userSelect", "none");
    }
  }
}






/*
---------------------------------------------------------------------------
  OPACITY
---------------------------------------------------------------------------
*/

/*!
Sets the opacity for the widget. Any child widget inside the widget will also
become (semi-)transparent. The value should be a number between 0 and 1
inclusive, where 1 means totally opaque and 0 invisible.
*/
if(qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifyOpacity = function(propValue, propOldValue, propData)
  {
    if(propValue == null || propValue >= 1 || propValue < 0)
    {
      this.removeStyleProperty("filter");
    }
    else if (qx.util.Validation.isValidNumber(propValue))
    {
      this.setStyleProperty("filter",
                            ("Alpha(Opacity=" +
                             Math.round(propValue * 100) +
                             ")"));
    }
    else
    {
      throw new Error("Unsupported opacity value: " + propValue);
    }

    return true;
  }
}
else
{
  qx.Proto._modifyOpacity = function(propValue, propOldValue, propData)
  {
    if(propValue == null || propValue > 1)
    {
      if (qx.sys.Client.getInstance().isGecko())
      {
        this.removeStyleProperty("MozOpacity");
      }
      else if (qx.sys.Client.getInstance().isKhtml())
      {
        this.removeStyleProperty("KhtmlOpacity");
      }

      this.removeStyleProperty("opacity");
    }
    else if (qx.util.Validation.isValidNumber(propValue))
    {
      propValue = qx.lang.Number.limit(propValue, 0, 1);

      // should we omit gecko's flickering here
      // and limit the max value to 0.99?

      if (qx.sys.Client.getInstance().isGecko())
      {
        this.setStyleProperty("MozOpacity", propValue);
      }
      else if (qx.sys.Client.getInstance().isKhtml())
      {
        this.setStyleProperty("KhtmlOpacity", propValue);
      }

      this.setStyleProperty("opacity", propValue);
    }

    return true;
  }
}






/*
---------------------------------------------------------------------------
  CURSOR
---------------------------------------------------------------------------
*/

qx.Proto._modifyCursor = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    if (propValue == "pointer" &&
        qx.sys.Client.getInstance().isMshtml()) {
    this.setStyleProperty("cursor",
                          "hand");
    } else {
    this.setStyleProperty("cursor",
                          propValue);
    }
  }
  else
  {
    this.removeStyleProperty("cursor");
  }

  return true;
}





/*
---------------------------------------------------------------------------
  BACKGROUND IMAGE
---------------------------------------------------------------------------
*/

qx.Proto._modifyBackgroundImage = function(propValue, propOldValue, propData)
{
  return qx.util.Validation.isValidString(propValue) ?
    this.setStyleProperty("backgroundImage",
      "url(" +
      qx.manager.object.AliasManager.getInstance().resolvePath(propValue) +
      ")") :
    this.removeStyleProperty("backgroundImage");
}






/*
---------------------------------------------------------------------------
  CLIPPING
---------------------------------------------------------------------------
*/

qx.Proto._modifyClip = function(propValue, propOldValue, propData) {
  return this._compileClipString();
}

qx.Proto._compileClipString = function()
{
  var vLeft = this.getClipLeft();
  var vTop = this.getClipTop();
  var vWidth = this.getClipWidth();
  var vHeight = this.getClipHeight();

  var vRight, vBottom;

  if(vLeft == null)
  {
    vRight = (vWidth == null
              ? "auto"
              : vWidth + "px");
    vLeft = "auto";
  }
  else
  {
    vRight = (vWidth == null
              ? "auto"
              : vLeft + vWidth + "px");
    vLeft = vLeft + "px";
  }

  if(vTop == null)
  {
    vBottom = (vHeight == null
               ? "auto"
               : vHeight + "px");
    vTop = "auto";
  }
  else
  {
    vBottom = (vHeight == null
               ? "auto"
               : vTop + vHeight + "px");
    vTop = vTop + "px";
  }

  return this.setStyleProperty("clip",
                               ("rect(" +
                                vTop +
                                "," +
                                vRight +
                                "," +
                                vBottom +
                                "," +
                                vLeft +
                                ")"));
}






/*
---------------------------------------------------------------------------
  OVERFLOW
---------------------------------------------------------------------------
*/

/*
  This will measure the typical native scrollbar size in the environment
*/
qx.ui.core.Widget.initOverflow = function()
{
  if (qx.ui.core.Widget.initOverflowDone) {
    return;
  }

  var t = document.createElement("div");
  var s = t.style;

  s.height = s.width = "100px";
  s.overflow = "scroll";

  document.body.appendChild(t);

  var c = qx.dom.Dimension.getScrollBarSizeRight(t);
  if (c) {
    qx.ui.core.Widget.SCROLLBAR_SIZE = c;
  }

  document.body.removeChild(t);

  qx.ui.core.Widget.initOverflowDone = true;
}

if (qx.sys.Client.getInstance().isGecko())
{
  qx.Proto._modifyOverflow = function(propValue, propOldValue, propData)
  {
    var pv = propValue;
    var pn = propData.name;

    switch(pv)
    {
      case "hidden":
        pv = "-moz-scrollbars-none";
        break;

      case "scrollX":
        pv = "-moz-scrollbars-horizontal";
        break;

      case "scrollY":
        pv = "-moz-scrollbars-vertical";
        break;
    }

    return this._applyOverflow(pn, pv, propValue, propOldValue);
  }
}

// Mshtml conforms here to CSS3 Spec. Eventually there will be multiple
// browsers which support these new overflowX overflowY properties.
else if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifyOverflow = function(propValue, propOldValue, propData)
  {
    var pv = propValue;
    var pn = propData.name;

    switch(pv)
    {
      case "scrollX":
        pn = "overflowX";
        pv = "scroll";
        break;

      case "scrollY":
        pn = "overflowY";
        pv = "scroll";
        break;
    }

    // Clear up concurrenting rules
    var a = [ "overflow",
              "overflowX",
              "overflowY" ];
    for (var i=0; i<a.length; i++)
    {
      if (a[i]!=pn) {
        this.removeStyleProperty(a[i]);
      }
    }

    return this._applyOverflow(pn, pv, propValue, propOldValue);
  }
}

// Opera/Khtml Mode...
// hopefully somewhat of this is supported in the near future.

// overflow-x and overflow-y are also not supported by Opera 9.0 Beta1
// and also not if we switch to IE emulation mode
else
{
  qx.Proto._modifyOverflow = function(propValue, propOldValue, propData)
  {
    var pv = propValue;
    var pn = propData.name;

    switch(pv)
    {
      case "scrollX":
      case "scrollY":
        pv = "scroll";
        break;
    }

    return this._applyOverflow(pn, pv, propValue, propOldValue);
  }
}

qx.Proto._applyOverflow = function(pn, pv, propValue, propOldValue)
{
  // Apply Style
  this.setStyleProperty(pn, pv);

  // Invalidate Frame
  this._invalidateFrameWidth();
  this._invalidateFrameHeight();

  return true;
}

qx.Proto.getOverflowX = function()
{
  var vOverflow = this.getOverflow();
  return vOverflow == "scrollY" ? "hidden" : vOverflow;
}

qx.Proto.getOverflowY = function()
{
  var vOverflow = this.getOverflow();
  return vOverflow == "scrollX" ? "hidden" : vOverflow;
}






/*
---------------------------------------------------------------------------
  HIDE FOCUS
---------------------------------------------------------------------------
*/

if (qx.sys.Client.getInstance().isMshtml())
{
  qx.Proto._modifyHideFocus = function(propValue, propOldValue, propData)
  {
    this.setHtmlProperty(propData.name, propValue);
    return true;
  }
}

// Need no implementation for others then mshtml, because
// all these browsers support css outlines and do not
// have an attribute "hideFocus" as IE.






/*
---------------------------------------------------------------------------
  COLORS
---------------------------------------------------------------------------
*/

qx.Proto._modifyBackgroundColor = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue)
  {
    this._applyBackgroundColor(propValue.getStyle());
    propValue.add(this);
  }
  else
  {
    this._resetBackgroundColor();
  }

  return true;
}

qx.Proto._modifyColor = function(propValue, propOldValue, propData)
{
  if (propOldValue) {
    propOldValue.remove(this);
  }

  if (propValue)
  {
    this._applyColor(propValue.getStyle());
    propValue.add(this);
  }
  else
  {
    this._resetColor();
  }

  return true;
}

qx.Proto._updateColors = function(vColor, vNewValue)
{
  if (this.getColor() == vColor) {
    this._applyColor(vNewValue);
  }

  if (this.getBackgroundColor() == vColor) {
    this._applyBackgroundColor(vNewValue);
  }
}

qx.Proto._applyColor = function(vNewValue) {
  this.setStyleProperty("color", vNewValue);
}

qx.Proto._applyBackgroundColor = function(vNewValue) {
  this.setStyleProperty("backgroundColor", vNewValue);
}

qx.Proto._resetColor = function(vNewValue) {
  this.removeStyleProperty("color");
}

qx.Proto._resetBackgroundColor = function() {
  this.removeStyleProperty("backgroundColor");
}






/*
---------------------------------------------------------------------------
  BORDER
---------------------------------------------------------------------------
*/

qx.Proto._cachedBorderTop = 0;
qx.Proto._cachedBorderRight = 0;
qx.Proto._cachedBorderBottom = 0;
qx.Proto._cachedBorderLeft = 0;

qx.Proto._modifyBorder = function(propValue, propOldValue, propData)
{
  var vOldTop = this._cachedBorderTop;
  var vOldRight = this._cachedBorderRight;
  var vOldBottom = this._cachedBorderBottom;
  var vOldLeft = this._cachedBorderLeft;

  if (propOldValue) {
    propOldValue.removeListenerWidget(this);
  }

  if (propValue)
  {
    propValue.addListenerWidget(this);

    this._cachedBorderTop = propValue.getTopWidth();
    this._cachedBorderRight = propValue.getRightWidth();
    this._cachedBorderBottom = propValue.getBottomWidth();
    this._cachedBorderLeft = propValue.getLeftWidth();
  }
  else
  {
    this._cachedBorderTop = this._cachedBorderRight = this._cachedBorderBottom = this._cachedBorderLeft = 0;
  }



  // ----------------
  // X-AXIS
  // ----------------
  if ((vOldLeft + vOldRight) != (this._cachedBorderLeft + this._cachedBorderRight)) {
    this._invalidateFrameWidth();
  }

  this.addToQueue("borderX");



  // ----------------
  // Y-AXIS
  // ----------------
  if ((vOldTop + vOldBottom) != (this._cachedBorderTop + this._cachedBorderBottom)) {
    this._invalidateFrameHeight();
  }

  this.addToQueue("borderY");





  return true;
}

qx.Proto.getCachedBorderTop = function() {
  return this._cachedBorderTop;
}

qx.Proto.getCachedBorderRight = function() {
  return this._cachedBorderRight;
}

qx.Proto.getCachedBorderBottom = function() {
  return this._cachedBorderBottom;
}

qx.Proto.getCachedBorderLeft = function() {
  return this._cachedBorderLeft;
}

qx.Proto._updateBorder = function(vEdge)
{
  // Small hack, remove later: TODO
  // ?? Anybody have an idea about this TODO?
  var vBorder = this.getBorder();
  var vEdgeUp = qx.lang.String.toFirstUp(vEdge);

  var vNewValue = vBorder["get" + vEdgeUp + "Width"]();
  var vCacheName = "_cachedBorder" + vEdgeUp;
  var vWidthChanged = this[vCacheName] != vNewValue;

  this[vCacheName] = vNewValue;

  switch(vEdge)
  {
    case "left":
    case "right":
      if (vWidthChanged) {
        this.addToJobQueue("borderWidthX");
      }

      this.addToJobQueue("borderX");
      break;

    case "top":
    case "bottom":
      if (vWidthChanged) {
        this.addToJobQueue("borderWidthY");
      }

      this.addToJobQueue("borderY");
      break;
  }
}







/*
---------------------------------------------------------------------------
  PADDING
---------------------------------------------------------------------------
*/

qx.Proto._modifyPaddingX = function(propValue, propOldValue, propData)
{
  this._invalidateFrameWidth();
  return true;
}

qx.Proto._modifyPaddingY = function(propValue, propOldValue, propData)
{
  this._invalidateFrameHeight();
  return true;
}






/*
---------------------------------------------------------------------------
  CLONE
---------------------------------------------------------------------------
*/

qx.Proto._clonePropertyIgnoreList = "parent,element,visible";


/*!
Returns a cloned copy of the current instance of qx.ui.core.Widget.

#param cloneRecursive[Boolean]: Should the widget cloned recursive (including all childs)?
#param customPropertyList[Array]: Optional (reduced) list of properties to copy through
*/

// TODO: Needs modification to work with new codebase
qx.Proto.clone = function(cloneRecursive, customPropertyList)
{
  var cloneInstance = new this.constructor;

  var propertyName;
  var propertyList = [];
  var propertyIngoreList = this._clonePropertyIgnoreList.split(",");

  // Build new filtered property list
  var sourcePropertyList = qx.util.Validation.isValid(customPropertyList) ? customPropertyList : this._properties.split(",");
  var sourcePropertyListLength = sourcePropertyList.length-1;
  do {
    propertyName = sourcePropertyList[sourcePropertyListLength];
    if (!qx.lang.Array.contains(propertyIngoreList, propertyName)) {
      propertyList.push(propertyName);
    }
  }
  while(sourcePropertyListLength--);

  // Apply properties to new clone instance
  propertyListLength = propertyList.length-1;
  do {
    propertyName = qx.lang.String.toFirstUp(propertyList[propertyListLength]);
    cloneInstance["set" + propertyName](this["get" + propertyName]());
  }
  while(propertyListLength--);

  // post apply parent info
  if (qx.lang.Array.contains(sourcePropertyList, "parent"))
  {
    var myParent = this.getParent();
    if (myParent) {
      cloneInstance.setParent(myParent);
    }
  }

  // clone recursion
  if (cloneRecursive) {
    this._cloneRecursive(cloneInstance);
  }

  return cloneInstance;
}

qx.Proto._cloneRecursive = function(cloneInstance) {}






/*
---------------------------------------------------------------------------
  COMMAND INTERFACE
---------------------------------------------------------------------------
*/

qx.Proto.execute = function()
{
  var vCommand = this.getCommand();
  if (vCommand) {
    vCommand.execute(this);
  }

  this.createDispatchEvent("execute");
}






/*
---------------------------------------------------------------------------
  NODE ALIASES
---------------------------------------------------------------------------
*/

qx.Proto._visualPropertyCheck = function()
{
  if (!this.isCreated()) {
    throw new Error("Element must be created previously!");
  }
}

qx.Proto.setScrollLeft = function(nScrollLeft)
{
  this._visualPropertyCheck();
  this._getTargetNode().scrollLeft = nScrollLeft;
}

qx.Proto.setScrollTop = function(nScrollTop)
{
  this._visualPropertyCheck();
  this._getTargetNode().scrollTop = nScrollTop;
}

qx.Proto.getOffsetLeft = function()
{
  this._visualPropertyCheck();
  return qx.dom.Offset.getLeft(this.getElement());
}

qx.Proto.getOffsetTop = function()
{
  this._visualPropertyCheck();
  return qx.dom.Offset.getTop(this.getElement());
}

qx.Proto.getScrollLeft = function()
{
  this._visualPropertyCheck();
  return this._getTargetNode().scrollLeft;
}

qx.Proto.getScrollTop = function()
{
  this._visualPropertyCheck();
  return this._getTargetNode().scrollTop;
}

qx.Proto.getClientWidth = function()
{
  this._visualPropertyCheck();
  return this._getTargetNode().clientWidth;
}

qx.Proto.getClientHeight = function()
{
  this._visualPropertyCheck();
  return this._getTargetNode().clientHeight;
}

qx.Proto.getOffsetWidth = function()
{
  this._visualPropertyCheck();
  return this.getElement().offsetWidth;
}

qx.Proto.getOffsetHeight = function()
{
  this._visualPropertyCheck();
  return this.getElement().offsetHeight;
}

qx.Proto.getScrollWidth = function()
{
  this._visualPropertyCheck();
  return this.getElement().scrollWidth;
}

qx.Proto.getScrollHeight = function()
{
  this._visualPropertyCheck();
  return this.getElement().scrollHeight;
}





/*
---------------------------------------------------------------------------
  SCROLL INTO VIEW
---------------------------------------------------------------------------
*/

qx.Proto.scrollIntoView = function(vAlignTopLeft)
{
  this.scrollIntoViewX(vAlignTopLeft);
  this.scrollIntoViewY(vAlignTopLeft);
}

qx.Proto.scrollIntoViewX = function(vAlignLeft)
{
  if (!this._isCreated || !this._isDisplayable) {
    return false;
  }

  return qx.dom.ScrollIntoView.scrollX(this.getElement(), vAlignLeft);
}

qx.Proto.scrollIntoViewY = function(vAlignTop)
{
  if (!this._isCreated || !this._isDisplayable) {
    return false;
  }

  return qx.dom.ScrollIntoView.scrollY(this.getElement(), vAlignTop);
}








/*
---------------------------------------------------------------------------
  DRAG AND DROP SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.supportsDrop = function(vDragCache) {
  return true;
}







/*
---------------------------------------------------------------------------
  FADING PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The amount of steps for the fade.
 */
qx.OO.addProperty({ name : 'fadeSteps', type : "number", allowNull : false, defaultValue : 10});
/*!
  The duration for the fade.
 */
qx.OO.addProperty({ name : 'fadeTime', type : "number", allowNull : false, defaultValue : 400});
/*!
  The time between the fade steps.
 */
qx.OO.addProperty({ name : 'fadeInterval', type : "number", allowNull : false, defaultValue : 40});
/*!
  The current state of a fade in progress.
 */
qx.OO.addProperty({ name : 'fadeCounter', type : "number", allowNull : false, defaultValue : 0});
/*!
  The amount of oppacity changed on each fade step.
 */
qx.OO.addProperty({ name : 'fadeUnit', type : "number", allowNull : false, defaultValue : 10});
/*!
  The maximum opacity for a fadeIn.
 */
qx.OO.addProperty({ name : 'fadeMax', type : "number", allowNull : false, defaultValue : 100});






/*
---------------------------------------------------------------------------
  FADING SUPPORT
---------------------------------------------------------------------------
*/
qx.ui.core.Widget.FADE_IN = 'FADE_IN';
qx.ui.core.Widget.FADE_OUT = 'FADE_OUT';
qx.ui.core.Widget.FADE_FINISHED = 'FADE_FINISHED';


qx.Proto.fadeIn = function(vSteps, vTime) {
  if(vSteps) this.setFadeSteps(vSteps);
  if(vTime) this.setFadeTime(vTime);
  this._fadeMode = qx.ui.core.Widget.FADE_IN;
  var timer = this.getFadeTimer();
  timer.addEventListener("interval", this._onInterval, this);
  timer.start();
}

qx.Proto.fadeOut = function(vSteps, vTime) {
  if(vSteps) this.setFadeSteps(vSteps);
  if(vTime) this.setFadeTime(vTime);
  this._fadeMode = qx.ui.core.Widget.FADE_OUT;
  var timer = this.getFadeTimer();
  timer.addEventListener("interval", this._onInterval, this);
  timer.start();
};

qx.Proto.getFadeTimer = function() {
  if(this._fadeTimer){
    this._fadeTimer.setInterval(this.getFadeInterval());
  } else {
    this._fadeTimer = new qx.client.Timer(this.getFadeInterval());
  };
  return this._fadeTimer;
};

qx.Proto.resetFader = function() {
  this.setFadeCounter(0);
  if(this.getFadeTimer()) {
    this._fadeTimer.stop();
    this._fadeTimer.dispose();
  };
  this._fadeTimer.dispose();
  this._fadeTimer = null;
};

qx.Proto._onInterval = function(e) {
  this.getFadeTimer().stop();
  var counter = this.getFadeCounter();
  switch (this._fadeMode){
    case qx.ui.core.Widget.FADE_IN:
      this.setFadeCounter(++counter);
      if(counter <= this.getFadeSteps()){
        this.setOpacity(this._computeFadeOpacity());
        this.getFadeTimer().restart();
      } else if(this.hasEventListeners(qx.ui.core.Widget.FADE_FINISHED)) {
        this.createDispatchDataEvent(qx.ui.core.Widget.FADE_FINISHED, qx.ui.core.Widget.FADE_IN);
      };
    break;

    case qx.ui.core.Widget.FADE_OUT:
      this.setFadeCounter(--counter);
      if(counter >= 0){
        this.setOpacity(this._computeFadeOpacity());
        this.getFadeTimer().restart();
      } else if(this.hasEventListeners(qx.ui.core.Widget.FADE_FINISHED)) {
        this.createDispatchDataEvent(qx.ui.core.Widget.FADE_FINISHED, qx.ui.core.Widget.FADE_OUT);
      };
      break;
    };
    qx.ui.core.Widget.flushGlobalQueues();
};

qx.Proto._modifyFadeSteps = function(propValue, propOldValue, propData) {
  if(propValue < 1) return;
  this.setFadeInterval(parseInt(this.getFadeTime() / propValue));
  this.setFadeUnit(Math.round(this.getFadeMax()/propValue));
  return true;
};

qx.Proto._modifyFadeTime = function(propValue, propOldValue, propData) {
  if(propValue < 1) return;
  this.setFadeInterval(parseInt(propValue / this.getFadeSteps()));
  return true;
};

qx.Proto._modifyFadeUnit = function(propValue, propOldValue, propData) {
  this.setFadeSteps(Math.round(this.getFadeMax()/propValue));
  return true;
};

qx.Proto._modifyFadeMax = function(propValue, propOldValue, propData) {
  this.setFadeUnit(Math.round(propValue / this.getFadeSteps()));
  return true;
};

qx.Proto._computeFadeOpacity = function() {
  var op = this.getFadeUnit() * this.getFadeCounter() / 100;
  return(op);
};








/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/
qx.Proto.dispose = function()
{
  if(this.getDisposed()) {
    return;
  }

  var vElement = this.getElement();

  if (vElement)
  {
    this._removeInlineEvents(vElement);

    delete this._isCreated;

    vElement.qx_Widget = null;

    this._element = null;
    this._style = null;
  }

  this._inlineEvents = null;
  this._element = null;
  this._style = null;
  this._borderElement = null;
  this._borderStyle = null;
  this._oldParent = null;

  // should be enough to remove the hashTables
  delete this._styleProperties;
  delete this._htmlProperties;
  delete this._htmlAttributes;
  delete this._states;

  // remove queue content
  for (var i in this._jobQueue) {
    delete this._jobQueue[i];
  }
  delete this._jobQueue;

  for (var i in this._layoutChanges) {
    delete this._layoutChanges[i];
  }
  delete this._layoutChanges;

  // dispose the fader
  if(this._fadeTimer){
    this._fadeTimer.dispose();
    this._fadeTimer = null;
  }

  return qx.core.Target.prototype.dispose.call(this);
}
