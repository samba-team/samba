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

#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.ui.layout.FlowLayout", qx.ui.core.Parent,
function() {
  qx.ui.core.Parent.call(this);
});

/*!
  The spacing between childrens. Could be any positive integer value.
*/
qx.OO.addProperty({ name : "horizontalSpacing", type : "number", defaultValue : 0, addToQueueRuntime : true, impl : "layout" });

/*!
  The spacing between childrens. Could be any positive integer value.
*/
qx.OO.addProperty({ name : "verticalSpacing", type : "number", defaultValue : 0, addToQueueRuntime : true, impl : "layout" });

/*!
  The horizontal align of the children. Allowed values are: "left" and "right"
*/
qx.OO.addProperty({ name : "horizontalChildrenAlign", type : "string", defaultValue : "left", possibleValues : [ "left", "right" ], addToQueueRuntime : true });

/*!
  The vertical align of the children. Allowed values are: "top" and "bottom"
*/
qx.OO.addProperty({ name : "verticalChildrenAlign", type : "string", defaultValue : "top", possibleValues : [ "top", "bottom" ], addToQueueRuntime : true });

/*!
  Should the children be layouted in reverse order?
*/
qx.OO.addProperty({ name : "reverseChildrenOrder", type : "boolean", defaultValue : false, addToQueueRuntime : true, impl : "layout" });






/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return new qx.renderer.layout.FlowLayoutImpl(this);
}





/*
---------------------------------------------------------------------------
  DIMENSION CACHE
---------------------------------------------------------------------------
*/

qx.Proto._changeInnerWidth = function(vNew, vOld)
{
  qx.ui.core.Parent.prototype._changeInnerWidth.call(this, vNew, vOld);

  // allow 'auto' values for height to update when the inner width changes
  this._invalidatePreferredInnerHeight();
}




/*
---------------------------------------------------------------------------
  MODIFIER
---------------------------------------------------------------------------
*/

qx.Proto._modifyLayout = function(propValue, propOldValue, propData)
{
  // invalidate inner preferred dimensions
  this._invalidatePreferredInnerDimensions();

  return true;
}
