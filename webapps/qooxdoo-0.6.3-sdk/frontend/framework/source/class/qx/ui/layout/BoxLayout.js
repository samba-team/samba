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

#module(ui_basic)
#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.ui.layout.BoxLayout", qx.ui.core.Parent,
function(vOrientation)
{
  qx.ui.core.Parent.call(this);

  // apply orientation
  if (qx.util.Validation.isValidString(vOrientation)) {
    this.setOrientation(vOrientation);
  }
});

qx.ui.layout.BoxLayout.STR_REVERSED = "-reversed";



/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  The orientation of the layout control. Allowed values are "horizontal" (default) and "vertical".
*/
qx.OO.addProperty({ name : "orientation", type : "string", possibleValues : [ "horizontal", "vertical" ], addToQueueRuntime : true });

/*!
  The spacing between childrens. Could be any positive integer value.
*/
qx.OO.addProperty({ name : "spacing", type : "number", defaultValue : 0, addToQueueRuntime : true, impl : "layout" });

/*!
  The horizontal align of the children. Allowed values are: "left", "center" and "right"
*/
qx.OO.addProperty({ name : "horizontalChildrenAlign", type : "string", defaultValue : "left", possibleValues : [ "left", "center", "right" ], impl : "layoutOrder", addToQueueRuntime : true });

/*!
  The vertical align of the children. Allowed values are: "top", "middle" and "bottom"
*/
qx.OO.addProperty({ name : "verticalChildrenAlign", type : "string", defaultValue : "top", possibleValues : [ "top", "middle", "bottom" ], impl : "layoutOrder", addToQueueRuntime : true });

/*!
  Should the children be layouted in reverse order?
*/
qx.OO.addProperty({ name : "reverseChildrenOrder", type : "boolean", defaultValue : false, impl : "layoutOrder", addToQueueRuntime : true });

/*!
  Should the widgets be stretched to the available width (orientation==vertical) or height (orientation==horizontal)?
  This only applies if the child has not configured a own value for this axis.
*/
qx.OO.addProperty({ name : "stretchChildrenOrthogonalAxis", type : "boolean", defaultValue : true, addToQueueRuntime : true });

/*!
  If there are min/max values in combination with flex try to optimize placement.
  This is more complex and produces more time for the layouter but sometimes this feature is needed.
*/
qx.OO.addProperty({ name : "useAdvancedFlexAllocation", type : "boolean", defaultValue : false, addToQueueRuntime : true });





/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return this.getOrientation() == "vertical" ? new qx.renderer.layout.VerticalBoxLayoutImpl(this) : new qx.renderer.layout.HorizontalBoxLayoutImpl(this);
}






/*
---------------------------------------------------------------------------
  HELPERS
---------------------------------------------------------------------------
*/

qx.Proto._layoutHorizontal = false;
qx.Proto._layoutVertical = false;
qx.Proto._layoutMode = "left";

qx.Proto.isHorizontal = function() {
  return this._layoutHorizontal;
}

qx.Proto.isVertical = function() {
  return this._layoutVertical;
}

qx.Proto.getLayoutMode = function()
{
  if (this._layoutMode == null) {
    this._updateLayoutMode();
  }

  return this._layoutMode;
}

qx.Proto._updateLayoutMode = function()
{
  this._layoutMode = this._layoutVertical ? this.getVerticalChildrenAlign() : this.getHorizontalChildrenAlign();

  if (this.getReverseChildrenOrder()) {
    this._layoutMode += qx.ui.layout.BoxLayout.STR_REVERSED;
  }
}

qx.Proto._invalidateLayoutMode = function() {
  this._layoutMode = null;
}






/*
---------------------------------------------------------------------------
  MODIFIERS
---------------------------------------------------------------------------
*/

qx.Proto._modifyOrientation = function(propValue, propOldValue, propData)
{
  // update fast access variables
  this._layoutHorizontal = propValue == "horizontal";
  this._layoutVertical = propValue == "vertical";

  // Layout Implementation
  if (this._layoutImpl)
  {
    this._layoutImpl.dispose();
    this._layoutImpl = null;
  }

  if (qx.util.Validation.isValidString(propValue)) {
    this._layoutImpl = this._createLayoutImpl();
  }

  // call other core modifier
  return this._modifyLayoutOrder(propValue, propOldValue, propData);
}

qx.Proto._modifyLayoutOrder = function(propValue, propOldValue, propData)
{
  // update layout mode
  this._invalidateLayoutMode();

  // call other core modifier
  return this._modifyLayout(propValue, propOldValue, propData);
}

qx.Proto._modifyLayout = function(propValue, propOldValue, propData)
{
  // invalidate inner preferred dimensions
  this._invalidatePreferredInnerDimensions();

  // accumulated width needs to be invalidated
  this._invalidateAccumulatedChildrenOuterWidth();
  this._invalidateAccumulatedChildrenOuterHeight();

  // make property handling happy :)
  return true;
}





/*
---------------------------------------------------------------------------
  ACCUMULATED CHILDREN WIDTH/HEIGHT
--------------------------------------------------------------------------------

  Needed for center/middle and right/bottom alignment

---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "accumulatedChildrenOuterWidth", defaultValue : null });
qx.OO.addCachedProperty({ name : "accumulatedChildrenOuterHeight", defaultValue : null });

qx.Proto._computeAccumulatedChildrenOuterWidth = function()
{
  var ch=this.getVisibleChildren(), chc, i=-1, sp=this.getSpacing(), s=-sp;

  while(chc=ch[++i]) {
    s += chc.getOuterWidth() + sp;
  }

  return s;
}

qx.Proto._computeAccumulatedChildrenOuterHeight = function()
{
  var ch=this.getVisibleChildren(), chc, i=-1, sp=this.getSpacing(), s=-sp;

  while(chc=ch[++i]) {
    s += chc.getOuterHeight() + sp;
  }

  return s;
}







/*
---------------------------------------------------------------------------
  STRETCHING SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto._recomputeChildrenStretchingX = function()
{
  var ch=this.getVisibleChildren(), chc, i=-1;

  while(chc=ch[++i])
  {
    if (chc._recomputeStretchingX() && chc._recomputeBoxWidth()) {
      chc._recomputeOuterWidth();
    }
  }
}

qx.Proto._recomputeChildrenStretchingY = function()
{
  var ch=this.getVisibleChildren(), chc, i=-1;

  while(chc=ch[++i])
  {
    if (chc._recomputeStretchingY() && chc._recomputeBoxHeight()) {
      chc._recomputeOuterHeight();
    }
  }
}
