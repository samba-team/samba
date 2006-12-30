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
#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.renderer.layout.CanvasLayoutImpl", qx.renderer.layout.LayoutImpl,
function(vWidget) {
  qx.renderer.layout.LayoutImpl.call(this, vWidget);
});



/*!
  Global Structure:
  [01] COMPUTE BOX DIMENSIONS FOR AN INDIVIDUAL CHILD
  [02] COMPUTE NEEDED DIMENSIONS FOR AN INDIVIDUAL CHILD
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
  [05] UPDATE CHILD ON INNER DIMENSION CHANGES OF LAYOUT
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
  [07] UPDATE CHILDREN ON JOB QUEUE FLUSH
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
  [09] FLUSH LAYOUT QUEUES OF CHILDREN
  [10] LAYOUT CHILD
  [11] DISPOSER


  Inherits from qx.renderer.layout.LayoutImpl:
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
  [07] UPDATE CHILDREN ON JOB QUEUE FLUSH
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
  [09] FLUSH LAYOUT QUEUES OF CHILDREN
  [11] DISPOSER
*/



/*
---------------------------------------------------------------------------
  [01] COMPUTE BOX DIMENSIONS FOR AN INDIVIDUAL CHILD
---------------------------------------------------------------------------
*/

/*!
  Compute and return the box width of the given child
*/
qx.Proto.computeChildBoxWidth = function(vChild)
{
  var vValue = null;

  if (vChild._computedLeftTypeNull || vChild._computedRightTypeNull)
  {
    vValue = vChild.getWidthValue();
  }
  else if (vChild._hasParent)
  {
    vValue = this.getWidget().getInnerWidth() - vChild.getLeftValue() - vChild.getRightValue();
  }

  return vValue || vChild._computeBoxWidthFallback();
}

/*!
  Compute and return the box height of the given child
*/
qx.Proto.computeChildBoxHeight = function(vChild)
{
  var vValue = null;

  if (vChild._computedTopTypeNull || vChild._computedBottomTypeNull)
  {
    vValue = vChild.getHeightValue();
  }
  else if (vChild._hasParent)
  {
    vValue = this.getWidget().getInnerHeight() - vChild.getTopValue() - vChild.getBottomValue();
  }

  return vValue || vChild._computeBoxHeightFallback();
}





/*
---------------------------------------------------------------------------
  [02] COMPUTE NEEDED DIMENSIONS FOR AN INDIVIDUAL CHILD
---------------------------------------------------------------------------
*/

/*!
  Compute and return the needed width of the given child
*/
qx.Proto.computeChildNeededWidth = function(vChild)
{
  var vLeft = vChild._computedLeftTypePercent ? null : vChild.getLeftValue();
  var vRight = vChild._computedRightTypePercent ? null : vChild.getRightValue();
  var vMinBox = vChild._computedMinWidthTypePercent ? null : vChild.getMinWidthValue();
  var vMaxBox = vChild._computedMaxWidthTypePercent ? null : vChild.getMaxWidthValue();

  if (vLeft != null && vRight != null)
  {
    var vBox = vChild.getPreferredBoxWidth() || 0;
  }
  else
  {
    var vBox = (vChild._computedWidthTypePercent ? null : vChild.getWidthValue()) || vChild.getPreferredBoxWidth() || 0;
  }

  return qx.lang.Number.limit(vBox, vMinBox, vMaxBox) + vLeft + vRight + vChild.getMarginLeft() + vChild.getMarginRight();
}

/*!
  Compute and return the needed height of the given child
*/
qx.Proto.computeChildNeededHeight = function(vChild)
{
  var vTop = vChild._computedTopTypePercent ? null : vChild.getTopValue();
  var vBottom = vChild._computedBottomTypePercent ? null : vChild.getBottomValue();
  var vMinBox = vChild._computedMinHeightTypePercent ? null : vChild.getMinHeightValue();
  var vMaxBox = vChild._computedMaxHeightTypePercent ? null : vChild.getMaxHeightValue();

  if (vTop != null && vBottom != null)
  {
    var vBox = vChild.getPreferredBoxHeight() || 0;
  }
  else
  {
    var vBox = (vChild._computedHeightTypePercent ? null : vChild.getHeightValue()) || vChild.getPreferredBoxHeight() || 0;
  }

  return qx.lang.Number.limit(vBox, vMinBox, vMaxBox) + vTop + vBottom + vChild.getMarginTop() + vChild.getMarginBottom();
}






/*
---------------------------------------------------------------------------
  [05] UPDATE CHILD ON INNER DIMENSION CHANGES OF LAYOUT
---------------------------------------------------------------------------
*/

/*!
  Actions that should be done if the inner width of the widget was changed.
  Normally this includes update to percent values and ranges.
*/
qx.Proto.updateChildOnInnerWidthChange = function(vChild)
{
  // this makes sure that both functions get executed before return
  var vUpdatePercent = vChild._recomputePercentX();
  var vUpdateRange = vChild._recomputeRangeX();

  return vUpdatePercent || vUpdateRange;
}

/*!
  Actions that should be done if the inner height of the widget was changed.
  Normally this includes update to percent values and ranges.
*/
qx.Proto.updateChildOnInnerHeightChange = function(vChild)
{
  // this makes sure that both functions get executed before return
  var vUpdatePercent = vChild._recomputePercentY();
  var vUpdateRange = vChild._recomputeRangeY();

  return vUpdatePercent || vUpdateRange;
}





/*
---------------------------------------------------------------------------
  [10] LAYOUT CHILD
---------------------------------------------------------------------------
*/

/*!
  This is called from qx.ui.core.Widget and  it's task is to apply the layout
  (excluding border and padding) to the child.
*/
qx.Proto.layoutChild = function(vChild, vJobs)
{
  this.layoutChild_sizeX_essentialWrapper(vChild, vJobs);
  this.layoutChild_sizeY_essentialWrapper(vChild, vJobs);

  this.layoutChild_sizeLimitX(vChild, vJobs);
  this.layoutChild_sizeLimitY(vChild, vJobs);

  this.layoutChild_locationX(vChild, vJobs);
  this.layoutChild_locationY(vChild, vJobs);

  this.layoutChild_marginX(vChild, vJobs);
  this.layoutChild_marginY(vChild, vJobs);
}

if (qx.sys.Client.getInstance().isMshtml() || qx.sys.Client.getInstance().isOpera())
{
  qx.Proto.layoutChild_sizeX = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.width || vJobs.minWidth || vJobs.maxWidth || vJobs.left || vJobs.right)
    {
      if (vChild._computedMinWidthTypeNull && vChild._computedWidthTypeNull && vChild._computedMaxWidthTypeNull && !(!vChild._computedLeftTypeNull && !vChild._computedRightTypeNull))
      {
        vChild._resetRuntimeWidth();
      }
      else
      {
        vChild._applyRuntimeWidth(vChild.getBoxWidth());
      }
    }
  }

  qx.Proto.layoutChild_sizeY = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.height || vJobs.minHeight || vJobs.maxHeight || vJobs.top || vJobs.bottom)
    {
      if (vChild._computedMinHeightTypeNull && vChild._computedHeightTypeNull && vChild._computedMaxHeightTypeNull && !(!vChild._computedTopTypeNull && !vChild._computedBottomTypeNull))
      {
        vChild._resetRuntimeHeight();
      }
      else
      {
        vChild._applyRuntimeHeight(vChild.getBoxHeight());
      }
    }
  }
}
else
{
  qx.Proto.layoutChild_sizeX = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.width) {
      vChild._computedWidthTypeNull ? vChild._resetRuntimeWidth() : vChild._applyRuntimeWidth(vChild.getWidthValue());
    }
  }

  qx.Proto.layoutChild_sizeY = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.height) {
      vChild._computedHeightTypeNull ? vChild._resetRuntimeHeight() : vChild._applyRuntimeHeight(vChild.getHeightValue());
    }
  }
}

qx.Proto.layoutChild_locationX = function(vChild, vJobs)
{
  var vWidget = this.getWidget();

  if (vJobs.initial || vJobs.left || vJobs.parentPaddingLeft) {
    vChild._computedLeftTypeNull ? vChild._computedRightTypeNull && vWidget.getPaddingLeft() > 0 ? vChild._applyRuntimeLeft(vWidget.getPaddingLeft()) : vChild._resetRuntimeLeft() : vChild._applyRuntimeLeft(vChild.getLeftValue() + vWidget.getPaddingLeft());
  }

  if (vJobs.initial || vJobs.right || vJobs.parentPaddingRight) {
    vChild._computedRightTypeNull ? vChild._computedLeftTypeNull && vWidget.getPaddingRight() > 0 ? vChild._applyRuntimeRight(vWidget.getPaddingRight()) : vChild._resetRuntimeRight() : vChild._applyRuntimeRight(vChild.getRightValue() + vWidget.getPaddingRight());
  }
}

qx.Proto.layoutChild_locationY = function(vChild, vJobs)
{
  var vWidget = this.getWidget();

  if (vJobs.initial || vJobs.top || vJobs.parentPaddingTop) {
    vChild._computedTopTypeNull ? vChild._computedBottomTypeNull && vWidget.getPaddingTop() > 0 ? vChild._applyRuntimeTop(vWidget.getPaddingTop()) : vChild._resetRuntimeTop() : vChild._applyRuntimeTop(vChild.getTopValue() + vWidget.getPaddingTop());
  }

  if (vJobs.initial || vJobs.bottom || vJobs.parentPaddingBottom) {
    vChild._computedBottomTypeNull ? vChild._computedTopTypeNull && vWidget.getPaddingBottom() > 0 ? vChild._applyRuntimeBottom(vWidget.getPaddingBottom()) : vChild._resetRuntimeBottom() : vChild._applyRuntimeBottom(vChild.getBottomValue() + vWidget.getPaddingBottom());
  }
}
