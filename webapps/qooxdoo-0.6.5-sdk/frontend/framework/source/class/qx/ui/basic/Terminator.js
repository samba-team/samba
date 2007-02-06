/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2007 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL: http://www.gnu.org/licenses/lgpl.html
     EPL: http://www.eclipse.org/org/documents/epl-v10.php
     See the LICENSE file in the project's top-level directory for details.

   Authors:
     * Sebastian Werner (wpbasti)
     * Andreas Ecker (ecker)

************************************************************************ */

/* ************************************************************************

#module(ui_core)

************************************************************************ */

/*!
  This widget is the last widget of the current child chain.
*/
qx.OO.defineClass("qx.ui.basic.Terminator", qx.ui.core.Widget,
function() {
  qx.ui.core.Widget.call(this);
});






/*
---------------------------------------------------------------------------
  APPLY PADDING
---------------------------------------------------------------------------
*/

qx.Proto._applyPaddingX = function(vParent, vChanges, vStyle)
{
  if (vChanges.paddingLeft) {
    this._applyRuntimePaddingLeft(this.getPaddingLeft());
  }

  if (vChanges.paddingRight) {
    this._applyRuntimePaddingRight(this.getPaddingRight());
  }
}

qx.Proto._applyPaddingY = function(vParent, vChanges, vStyle)
{
  if (vChanges.paddingTop) {
    this._applyRuntimePaddingTop(this.getPaddingTop());
  }

  if (vChanges.paddingBottom) {
    this._applyRuntimePaddingBottom(this.getPaddingBottom());
  }
}






/*
---------------------------------------------------------------------------
  APPLY CONTENT
---------------------------------------------------------------------------
*/

qx.Proto._applyContent = function()
{
  // Small optimization: Only add innerPreferred jobs
  // if we don't have a static width
  if (this._computedWidthTypePixel) {
    this._cachedPreferredInnerWidth = null;
  } else {
    this._invalidatePreferredInnerWidth();
  }

  // Small optimization: Only add innerPreferred jobs
  // if we don't have a static height
  if (this._computedHeightTypePixel) {
    this._cachedPreferredInnerHeight = null;
  } else {
    this._invalidatePreferredInnerHeight();
  }

  // add load job
  if (this._initialLayoutDone) {
    this.addToJobQueue("load");
  }
}

qx.Proto._layoutPost = function(vChanges) {
  if (vChanges.initial || vChanges.load || vChanges.width || vChanges.height) {
    this._postApply();
  }
}

qx.Proto._postApply = qx.lang.Function.returnTrue;







/*
---------------------------------------------------------------------------
  BOX DIMENSION HELPERS
---------------------------------------------------------------------------
*/

qx.Proto._computeBoxWidthFallback = qx.Proto.getPreferredBoxWidth;
qx.Proto._computeBoxHeightFallback = qx.Proto.getPreferredBoxHeight;

qx.Proto._computePreferredInnerWidth = qx.lang.Function.returnZero;
qx.Proto._computePreferredInnerHeight = qx.lang.Function.returnZero;







/*
---------------------------------------------------------------------------
  METHODS TO GIVE THE LAYOUTERS INFORMATIONS
---------------------------------------------------------------------------
*/

qx.Proto._isWidthEssential = function()
{
  if (!this._computedLeftTypeNull && !this._computedRightTypeNull) {
    return true;
  }

  if (!this._computedWidthTypeNull && !this._computedWidthTypeAuto) {
    return true;
  }

  if (!this._computedMinWidthTypeNull && !this._computedMinWidthTypeAuto) {
    return true;
  }

  if (!this._computedMaxWidthTypeNull && !this._computedMaxWidthTypeAuto) {
    return true;
  }

  if (this._borderElement) {
    return true;
  }

  return false;
}

qx.Proto._isHeightEssential = function()
{
  if (!this._computedTopTypeNull && !this._computedBottomTypeNull) {
    return true;
  }

  if (!this._computedHeightTypeNull && !this._computedHeightTypeAuto) {
    return true;
  }

  if (!this._computedMinHeightTypeNull && !this._computedMinHeightTypeAuto) {
    return true;
  }

  if (!this._computedMaxHeightTypeNull && !this._computedMaxHeightTypeAuto) {
    return true;
  }

  if (this._borderElement) {
    return true;
  }

  return false;
}
