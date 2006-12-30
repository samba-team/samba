/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Volker Pauli (vpauli)
     * Sebastian Werner (wpbasti)
     * Carsten Lergenmueller (carstenL)

 ************************************************************************ */

/* ************************************************************************

#module(ui_splitpane)

 ************************************************************************ */


/**
 * Creates a new instance of a SplitPane. It allows the user to dynamically resize
 * the areas dropping the border between.
 *
 * new qx.ui.splitpane.SplitPane(orientation)
 * new qx.ui.splitpane.SplitPane(orientation, firstSize, secondSize)
 *
 * @param orientation {string} The orientation of the splitpane control. Allowed values are "horizontal" (default) and "vertical". This is the same type as used in {@link qx.ui.layout.BoxLayout#orientation}.
 * @param firstSize {string} The size of the left (top) pane. Allowed values are any by {@link qx.ui.core.Widget} supported unit.
 * @param secondSize {string} The size of the right (bottom) pane. Allowed values are any by {@link qx.ui.core.Widget} supported unit.
 */
qx.OO.defineClass("qx.ui.splitpane.SplitPane", qx.ui.layout.CanvasLayout,
function(orientation, firstSize, secondSize)
{
  qx.ui.layout.CanvasLayout.call(this);

  // CREATE INNER BOX LAYOUT
  var box = this._box = new qx.ui.layout.BoxLayout;
  box.setEdge(0);
  this.add(box);

  /*

  the splitpane itself is a boxlayout resides on top of a canvas for easier computing of positional values

  ---------------------------------------------------------------------------------------
  |  canvas                                                                               |
  |  -----------------------------------------------------------------------------------  |
  | | box                                                                               | |
  | | ---------------------------  ---  ----------------------------------------------- | |
  | | |                         |  | |  |                                             | | |
  | | | firstArea               |  |s|  | secondArea                                  | | |
  | | |                         |  |p|  |                                             | | |
  | | |                         |  |l|  |                                             | | |
  | | |                         |  |i|  |                                             | | |
  | | |                         |  |t|  |                                             | | |
  | | |                         |  |t|  |                                             | | |
  | | |                         |  |e|  |                                             | | |
  | | |                         |  |r|  |                                             | | |
  | | |                         |  | |  |                                             | | |
  | | ---------------------------  ---  ----------------------------------------------- | |
  |  -----------------------------------------------------------------------------------  |
  |                                                                                       |
  ---------------------------------------------------------------------------------------

  */

  // CREATE SLIDER
  this._slider = new qx.ui.layout.CanvasLayout;
  this._slider.setAppearance("splitpane-slider");
  this._slider.setStyleProperty("fontSize", "0px");
  this._slider.setStyleProperty("lineHeight", "0px");
  this._slider.hide();
  this._slider._pane = this;
  this.add(this._slider);

  // CREATE SPLITTER
  this._splitter = new qx.ui.layout.CanvasLayout;
  this._splitter.setStyleProperty("fontSize", "0px");
  this._splitter.setStyleProperty("lineHeight", "0px");
  this._splitter.setAppearance("splitpane-splitter");
  this._splitter._pane = this;

  // PATCH METHODS
  this._slider._applyRuntimeLeft = this._splitter._applyRuntimeLeft = this._applyRuntimeLeftWrapper;
  this._slider._applyRuntimeTop = this._splitter._applyRuntimeTop = this._applyRuntimeTopWrapper;

  // CREATE KNOB
  this._knob = new qx.ui.basic.Image;
  this._knob.setAppearance("splitpane-knob");
  this._knob.setVisibility(false);
  this.add(this._knob);

  // CREATE AREAS
  this._firstArea = new qx.ui.layout.CanvasLayout;
  this._secondArea = new qx.ui.layout.CanvasLayout;

  // FILL BOX
  box.add(this._firstArea, this._splitter, this._secondArea);

  // APPLY DIMENSIONS
  this.setFirstSize(firstSize || "1*");
  this.setSecondSize(secondSize || "1*");

  // APPLY ORIENTATION
  this.setOrientation(orientation || "horizontal");
});










/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
 */

/**
 * Appearance change
 */
qx.OO.changeProperty({ name : "appearance", defaultValue : "splitpane" });

/**
 * Show the knob
 */
qx.OO.addProperty({ name : "showKnob", type : "boolean", allowNull : false, defaultValue : false });

/**
 * The layout method for the splitpane. If true, the content will updated immediatly.
 */
qx.OO.addProperty({ name : "liveResize", type : "boolean", allowNull : false, defaultValue : false, getAlias : "isLiveResize"});

/**
 * The orientation of the splitpane control. Allowed values are "horizontal" (default) and "vertical".
 */
qx.OO.addProperty({ name : "orientation", type : "string", possibleValues : [ "horizontal", "vertical" ] });

/**
 * The size of the first (left/top) area.
 */
qx.OO.addProperty({ name : "firstSize" });

/**
 * The size of the second (right/bottom) area.
 */
qx.OO.addProperty({ name : "secondSize" });

/**
 * Size of the splitter
 */
qx.OO.addProperty({ name : "splitterSize", defaultValue : 4 });







/*
---------------------------------------------------------------------------
  PUBLIC METHODS
---------------------------------------------------------------------------
*/


/**
 * adds one or more widget(s) to the left pane
 *
 *@param widget (qx.ui.core.Parent)
 */
qx.Proto.addLeft = function() {
  var c = this.getFirstArea();
  return c.add.apply(c, arguments);
}

/**
 * adds one or more widget(s) to the top pane
 *
 *@param widget (qx.ui.core.Parent)
 */
qx.Proto.addTop = function() {
  var c = this.getFirstArea();
  return c.add.apply(c, arguments);
}

/**
 * adds one or more widget(s) to the right pane
 *
 *@param widget (qx.ui.core.Parent)
 */
qx.Proto.addRight = function() {
  var c = this.getSecondArea();
  return c.add.apply(c, arguments);
}

/**
 * adds one or more widget(s) to the bottom pane
 *
 *@param widget (qx.ui.core.Parent)
 */
qx.Proto.addBottom = function() {
  var c = this.getSecondArea();
  return c.add.apply(c, arguments);
}

/**
 * Returns the splitter.
 *
 * @return {qx.ui.core.Widget} The splitter.
 */
qx.Proto.getSplitter = function() {
  return this._splitter;
}

/**
 * Returns the knob.
 *
 * @return {qx.ui.core.Widget} The knob.
 */
qx.Proto.getKnob = function() {
  return this._knob;
}






/**
 * Returns the left area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getLeftArea = function() {
  return this.getFirstArea();
}

/**
 * Returns the top area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getTopArea = function() {
  return this.getFirstArea();
}

/**
 * Returns the right area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getRightArea = function() {
  return this.getSecondArea();
}

/**
 * Returns the bottom area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getBottomArea = function() {
  return this.getSecondArea();
}

/**
 * Returns the first area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getFirstArea = function() {
  return this._firstArea;
}

/**
 * Returns the second area (CanvasLayout)
 *
 * @return {qx.ui.layout.CanvasLayout}
 */
qx.Proto.getSecondArea = function() {
  return this._secondArea;
}









/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyShowKnob = function(propValue, propOldValue, propData)
{
  this._knob.setVisibility(propValue);
  return true;
}

qx.Proto._modifyOrientation = function(propValue, propOldValue, propData)
{
  // sync orientation to layout
  this._box.setOrientation(propValue);

  switch(propOldValue)
  {
    case "horizontal":
      // remove old listeners
      this._splitter.removeEventListener("mousedown", this._onSplitterMouseDownX, this);
      this._splitter.removeEventListener("mousemove", this._onSplitterMouseMoveX, this);
      this._splitter.removeEventListener("mouseup", this._onSplitterMouseUpX, this);
      this._knob.removeEventListener("mousedown", this._onSplitterMouseDownX, this);
      this._knob.removeEventListener("mousemove", this._onSplitterMouseMoveX, this);
      this._knob.removeEventListener("mouseup", this._onSplitterMouseUpX, this);

      // reconfigure states
      this._splitter.removeState("horizontal");
      this._knob.removeState("horizontal");

      // reset old dimensions
      this._firstArea.setWidth(null);
      this._secondArea.setWidth(null);
      this._splitter.setWidth(null);

      break;

    case "vertical":
      // remove old listeners
      this._splitter.removeEventListener("mousedown", this._onSplitterMouseDownY, this);
      this._splitter.removeEventListener("mousemove", this._onSplitterMouseMoveY, this);
      this._splitter.removeEventListener("mouseup", this._onSplitterMouseUpY, this);
      this._knob.removeEventListener("mousedown", this._onSplitterMouseDownY, this);
      this._knob.removeEventListener("mousemove", this._onSplitterMouseMoveY, this);
      this._knob.removeEventListener("mouseup", this._onSplitterMouseUpY, this);

      // reconfigure states
      this._splitter.removeState("vertical");
      this._knob.removeState("vertical");

      // reset old dimensions
      this._firstArea.setHeight(null);
      this._secondArea.setHeight(null);
      this._splitter.setHeight(null);

      break;
  }

  switch(propValue)
  {
    case "horizontal":
      // add new listeners
      this._splitter.addEventListener("mousemove", this._onSplitterMouseMoveX, this);
      this._splitter.addEventListener("mousedown", this._onSplitterMouseDownX, this);
      this._splitter.addEventListener("mouseup", this._onSplitterMouseUpX, this);
      this._knob.addEventListener("mousemove", this._onSplitterMouseMoveX, this);
      this._knob.addEventListener("mousedown", this._onSplitterMouseDownX, this);
      this._knob.addEventListener("mouseup", this._onSplitterMouseUpX, this);

      // reconfigure states
      this._splitter.addState("horizontal");
      this._knob.addState("horizontal");

      // apply images
      this._knob.setSource("widget/splitpane/knob-horizontal.png");

      break;

    case "vertical":
      // add new listeners
      this._splitter.addEventListener("mousedown", this._onSplitterMouseDownY, this);
      this._splitter.addEventListener("mousemove", this._onSplitterMouseMoveY, this);
      this._splitter.addEventListener("mouseup", this._onSplitterMouseUpY, this);
      this._knob.addEventListener("mousedown", this._onSplitterMouseDownY, this);
      this._knob.addEventListener("mousemove", this._onSplitterMouseMoveY, this);
      this._knob.addEventListener("mouseup", this._onSplitterMouseUpY, this);

      // reconfigure states
      this._splitter.addState("vertical");
      this._knob.addState("vertical");

      // apply images
      this._knob.setSource("widget/splitpane/knob-vertical.png");

      break;
  }

  // apply new dimensions
  this._syncFirstSize();
  this._syncSecondSize();
  this._syncSplitterSize();

  return true;
};

qx.Proto._modifyFirstSize = function(propValue, propOldValue, propData)
{
  this._syncFirstSize();
  return true;
}

qx.Proto._modifySecondSize = function(propValue, propOldValue, propData)
{
  this._syncSecondSize();
  return true;
}

qx.Proto._modifySplitterSize = function(propValue, propOldValue, propData)
{
  this._syncSplitterSize();
  return true;
}

qx.Proto._syncFirstSize = function()
{
  switch(this.getOrientation())
  {
    case "horizontal":
      this._firstArea.setWidth(this.getFirstSize());
      break;

    case "vertical":
      this._firstArea.setHeight(this.getFirstSize());
      break;
  }
}

qx.Proto._syncSecondSize = function()
{
  switch(this.getOrientation())
  {
    case "horizontal":
      this._secondArea.setWidth(this.getSecondSize());
      break;

    case "vertical":
      this._secondArea.setHeight(this.getSecondSize());
      break;
  }
}

qx.Proto._syncSplitterSize = function()
{
  switch(this.getOrientation())
  {
    case "horizontal":
      this._splitter.setWidth(this.getSplitterSize());
      break;

    case "vertical":
      this._splitter.setHeight(this.getSplitterSize());
      break;
  }
}







/*
---------------------------------------------------------------------------
  EVENTS
---------------------------------------------------------------------------
*/

/**
 * Initializes drag session in case of a mousedown event on splitter in a horizontal splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseDownX = function(e)
{
  if (!e.isLeftButtonPressed()) {
    return;
  }

  this._commonMouseDown();

  // activate global cursor
  this.getTopLevelWidget().setGlobalCursor("col-resize");
  this._slider.addState("dragging");
  this._knob.addState("dragging");

  // initialize the drag session
  this._dragMin = qx.dom.Location.getPageInnerLeft(this._box.getElement());
  this._dragMax = this._dragMin + this._box.getInnerWidth() - this._splitter.getBoxWidth();
  this._dragOffset = e.getPageX() - qx.dom.Location.getPageBoxLeft(this._splitter.getElement());
}

/**
 * Initializes drag session in case of a mousedown event on splitter in a vertical splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseDownY = function(e)
{
  if (!e.isLeftButtonPressed()) {
    return;
  }

  this._commonMouseDown();

  // activate global cursor
  this.getTopLevelWidget().setGlobalCursor("row-resize");
  this._slider.addState("dragging");
  this._knob.addState("dragging");

  // initialize the drag session
  // dragStart = position of layout + mouse offset on splitter
  this._dragMin = qx.dom.Location.getPageInnerTop(this._box.getElement());
  this._dragMax = this._dragMin + this._box.getInnerHeight() - this._splitter.getBoxHeight();
  this._dragOffset = e.getPageY() - qx.dom.Location.getPageBoxTop(this._splitter.getElement());
}

qx.Proto._commonMouseDown = function()
{
  // enable capturing
  this._splitter.setCapture(true);

  // initialize the slider
  if(!this.isLiveResize())
  {
    this._slider.setLeft(this._splitter.getOffsetLeft());
    this._slider.setTop(this._splitter.getOffsetTop());
    this._slider.setWidth(this._splitter.getBoxWidth());
    this._slider.setHeight(this._splitter.getBoxHeight());

    this._slider.show();
  }
}








/**
 * Move the splitter in case of a mousemove event on splitter in a horizontal splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseMoveX = function(e)
{
  if (!this._splitter.getCapture()) {
    return;
  }

  this.isLiveResize() ? this._syncX(e) : this._slider._applyRuntimeLeft(this._normalizeX(e));
  e.preventDefault();
}

/**
 * Move the splitter in case of a mousemove event on splitter in a vertical splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseMoveY = function(e)
{
  if (!this._splitter.getCapture()) {
    return;
  }

  this.isLiveResize() ? this._syncY(e) : this._slider._applyRuntimeTop(this._normalizeY(e));
  e.preventDefault();
}







/**
 * Ends the drag session and computes the new dimensions of panes in case of a mouseup event on splitter in a horizontal splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseUpX = function(e)
{
  if (!this._splitter.getCapture()) {
    return;
  }

  if(!this.isLiveResize()) {
    this._syncX(e);
  }

  this._commonMouseUp();
}

/**
 * Ends the drag session and computes the new dimensions of panes in case of a mouseup event on splitter in a vertical splitpane.
 *
 * @param e {qx.event.MouseEvent} The event itself.
 */
qx.Proto._onSplitterMouseUpY = function(e)
{
  if (!this._splitter.getCapture()) {
    return;
  }

  if(!this.isLiveResize()) {
    this._syncY(e);
  }

  this._commonMouseUp();
}

qx.Proto._commonMouseUp = function()
{
  // hide helpers
  this._slider.hide();

  // disable capturing
  this._splitter.setCapture(false);

  // reset the global cursor
  this.getTopLevelWidget().setGlobalCursor(null);

  // cleanup dragsession
  this._slider.removeState("dragging");
  this._knob.removeState("dragging");
}

qx.Proto._syncX = function(e)
{
  var first = this._normalizeX(e);
  var second = this._box.getInnerWidth() - this._splitter.getBoxWidth() - first;

  this._syncCommon(first, second);
}

qx.Proto._syncY = function(e)
{
  var first = this._normalizeY(e);
  var second = this._box.getInnerHeight() - this._splitter.getBoxHeight() - first;

  this._syncCommon(first, second);
}

qx.Proto._syncCommon = function(first, second)
{
  this.setFirstSize(first + "*");
  this.setSecondSize(second + "*");
}

qx.Proto._normalizeX = function(e) {
  return qx.lang.Number.limit(e.getPageX() - this._dragOffset, this._dragMin, this._dragMax) - this._dragMin;
}

qx.Proto._normalizeY = function(e) {
  return qx.lang.Number.limit(e.getPageY() - this._dragOffset, this._dragMin, this._dragMax) - this._dragMin;
}

qx.Proto._applyRuntimeLeftWrapper = function(v)
{
  if (this._pane.getOrientation() == "horizontal") {
    this._pane._knob._applyRuntimeLeft(v);
  }

  return this.constructor.prototype._applyRuntimeLeft.call(this, v);
}

qx.Proto._applyRuntimeTopWrapper = function(v)
{
  if (this._pane.getOrientation() == "vertical") {
    this._pane._knob._applyRuntimeTop(v);
  }

  return this.constructor.prototype._applyRuntimeTop.call(this, v);
}





/*
------------------------------------------------------------------------------------
  DISPOSER
------------------------------------------------------------------------------------
 */

/**
 * Garbage collection
 */
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if(this._firstArea)
  {
    this._firstArea.dispose();
    this._firstArea = null;
  }

  if(this._secondArea)
  {
    this._secondArea.dispose();
    this._secondArea = null;
  }

  if (this._splitter)
  {
    this._splitter.removeEventListener("mousedown", this._onSplitterMouseDownX, this);
    this._splitter.removeEventListener("mouseup", this._onSplitterMouseMoveX, this);
    this._splitter.removeEventListener("mousemove", this._onSplitterMouseUpX, this);

    this._splitter.removeEventListener("mousedown", this._onSplitterMouseDownY, this);
    this._splitter.removeEventListener("mouseup", this._onSplitterMouseMoveY, this);
    this._splitter.removeEventListener("mousemove", this._onSplitterMouseUpY, this);

    this._splitter.dispose();
    this._splitter._pane = null;
    this._splitter = null;
  }

  if (this._slider)
  {
    this._slider.dispose();
    this._slider._pane = null;
    this._slider = null;
  }

  if (this._knob)
  {
    this._knob.removeEventListener("mousedown", this._onSplitterMouseDownX, this);
    this._knob.removeEventListener("mouseup", this._onSplitterMouseMoveX, this);
    this._knob.removeEventListener("mousemove", this._onSplitterMouseUpX, this);

    this._knob.removeEventListener("mousedown", this._onSplitterMouseDownY, this);
    this._knob.removeEventListener("mouseup", this._onSplitterMouseMoveY, this);
    this._knob.removeEventListener("mousemove", this._onSplitterMouseUpY, this);

    this._knob.dispose();
    this._knob = null;
  }

  return qx.ui.layout.BoxLayout.prototype.dispose.call(this);
}
