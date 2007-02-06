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
#module(ui_layout)
#require(qx.core.Client)

************************************************************************ */

/**
 * Abstact base class of all layout implementations
 *
 * @param vWidget {qx.ui.core.Parent} reference to the associated widget
 */
qx.OO.defineClass("qx.renderer.layout.LayoutImpl", qx.core.Object,
function(vWidget)
{
  qx.core.Object.call(this);

  this._widget = vWidget;
});




/**
 * Returns the associated widget
 *
 * @return {qx.ui.core.Parent} reference to the associated widget
 */
qx.Proto.getWidget = function() {
  return this._widget;
}


/*
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
*/


/*
---------------------------------------------------------------------------
  [01] COMPUTE BOX DIMENSIONS FOR AN INDIVIDUAL CHILD
---------------------------------------------------------------------------
*/

/**
 * Compute and return the box width of the given child
 *
 * @param vChild {qx.ui.core.Widget}
 * @return {Integer} box width of the given child
 */
qx.Proto.computeChildBoxWidth = function(vChild) {
  return vChild.getWidthValue() || vChild._computeBoxWidthFallback();
}

/**
 * Compute and return the box height of the given child
 *
 * @param vChild {qx.ui.core.Widget}
 * @return {Integer} box height of the given child
 */
qx.Proto.computeChildBoxHeight = function(vChild) {
  return vChild.getHeightValue() || vChild._computeBoxHeightFallback();
}





/*
---------------------------------------------------------------------------
  [02] COMPUTE NEEDED DIMENSIONS FOR AN INDIVIDUAL CHILD
---------------------------------------------------------------------------
*/

/**
 * Compute and return the needed width of the given child
 *
 * @param vChild {qx.ui.core.Widget}
 * @return {Integer} needed width
 */
qx.Proto.computeChildNeededWidth = function(vChild)
{
  // omit ultra long lines, these two variables only needed once
  // here, but this enhance the readability of the code :)
  var vMinBox = vChild._computedMinWidthTypePercent ? null : vChild.getMinWidthValue();
  var vMaxBox = vChild._computedMaxWidthTypePercent ? null : vChild.getMaxWidthValue();

  var vBox = (vChild._computedWidthTypePercent || vChild._computedWidthTypeFlex ? null : vChild.getWidthValue()) || vChild.getPreferredBoxWidth() || 0;

  return qx.lang.Number.limit(vBox, vMinBox, vMaxBox) + vChild.getMarginLeft() + vChild.getMarginRight();
}

/**
 * Compute and return the needed height of the given child
 *
 * @param vChild {qx.ui.core.Widget}
 * @return {Integer} needed height
 */
qx.Proto.computeChildNeededHeight = function(vChild)
{
  // omit ultra long lines, these two variables only needed once
  // here, but this enhance the readability of the code :)
  var vMinBox = vChild._computedMinHeightTypePercent ? null : vChild.getMinHeightValue();
  var vMaxBox = vChild._computedMaxHeightTypePercent ? null : vChild.getMaxHeightValue();

  var vBox = (vChild._computedHeightTypePercent || vChild._computedHeightTypeFlex ? null : vChild.getHeightValue()) || vChild.getPreferredBoxHeight() || 0;

  return qx.lang.Number.limit(vBox, vMinBox, vMaxBox) + vChild.getMarginTop() + vChild.getMarginBottom();
}




/*
---------------------------------------------------------------------------
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
---------------------------------------------------------------------------
*/

/**
 * Calculate the maximum needed width of all children
 *
 * @return {Integer} maximum needed width of all children
 */
qx.Proto.computeChildrenNeededWidth_max = function()
{
  for (var i=0, ch=this.getWidget().getVisibleChildren(), chl=ch.length, maxv=0; i<chl; i++) {
    maxv = Math.max(maxv, ch[i].getNeededWidth());
  }

  return maxv;
}

/**
 * Calculate the maximum needed height of all children
 *
 * @return {Integer} maximum needed height of all children
 */
qx.Proto.computeChildrenNeededHeight_max = function()
{
  for (var i=0, ch=this.getWidget().getVisibleChildren(), chl=ch.length, maxv=0; i<chl; i++) {
    maxv = Math.max(maxv, ch[i].getNeededHeight());
  }

  return maxv;
}

/**
 * Compute and return the width needed by all children of this widget
 *
 * @return {Integer}
 */
qx.Proto.computeChildrenNeededWidth_sum = function()
{
  for (var i=0, ch=this.getWidget().getVisibleChildren(), chl=ch.length, sumv=0; i<chl; i++) {
    sumv += ch[i].getNeededWidth();
  }

  return sumv;
}

/**
 * Compute and return the height needed by all children of this widget
 *
 * @return {Integer} height needed by all children of this widget
 */
qx.Proto.computeChildrenNeededHeight_sum = function()
{
  for (var i=0, ch=this.getWidget().getVisibleChildren(), chl=ch.length, sumv=0; i<chl; i++) {
    sumv += ch[i].getNeededHeight();
  }

  return sumv;
}

/**
 * Compute and return the width needed by all children of this widget
 *
 * @return {Integer} width needed by all children of this widget
 */
qx.Proto.computeChildrenNeededWidth = qx.Proto.computeChildrenNeededWidth_max;

/**
 * Compute and return the height needed by all children of this widget
 *
 * @return {Integer} height needed by all children of this widget
 */
qx.Proto.computeChildrenNeededHeight = qx.Proto.computeChildrenNeededHeight_max;




/*
---------------------------------------------------------------------------
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
---------------------------------------------------------------------------
*/

/**
 * Things to do and layout when any of the childs changes its outer width.
 * Needed by layouts where the children depend on each other, like flow or box layouts.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} changed child widget
 */
qx.Proto.updateSelfOnChildOuterWidthChange = function(vChild) {}

/**
 * Things to do and layout when any of the childs changes its outer height.
 * Needed by layouts where the children depend on each other, like flow or box layouts.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} changed child widget
 */
qx.Proto.updateSelfOnChildOuterHeightChange = function(vChild) {}





/*
---------------------------------------------------------------------------
  [05] UPDATE CHILD ON INNER DIMENSION CHANGES OF LAYOUT
---------------------------------------------------------------------------
*/

/**
 * Actions that should be done if the inner width of the layout widget has changed.
 * Normally this includes updates to percent values and ranges.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} changed child widget
 */
qx.Proto.updateChildOnInnerWidthChange = function(vChild) {}

/**
 * Actions that should be done if the inner height of the layout widget has changed.
 * Normally this includes updates to percent values and ranges.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} changed child widget
 */
qx.Proto.updateChildOnInnerHeightChange = function(vChild) {}





/*
---------------------------------------------------------------------------
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
---------------------------------------------------------------------------
*/

/**
 * Invalidate and recompute cached data according to job queue.
 * This is executed at the beginning of the job queue handling.
 *
 * Subclasses might implement this method
 *
 * @param vJobQueue {Object}
 */
qx.Proto.updateSelfOnJobQueueFlush = function(vJobQueue) {}






/*
---------------------------------------------------------------------------
  [07] UPDATE CHILDREN ON JOB QUEUE FLUSH
---------------------------------------------------------------------------
*/
/**
 * Updates children on job queue flush.
 * This is executed at the end of the job queue handling.
 *
 * Subclasses might implement this method
 *
 * @param vJobQueue {Object}
 */
qx.Proto.updateChildrenOnJobQueueFlush = function(vJobQueue) {}






/*
---------------------------------------------------------------------------
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
---------------------------------------------------------------------------
*/

/**
 * Add child to current layout. Rarely needed by some layout implementations.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} newly added child
 * @param vIndex {Integer} index of the child
 */
qx.Proto.updateChildrenOnAddChild = function(vChild, vIndex) {}

/**
 *Remove child from current layout.
 * Needed by layouts where the children depend on each other, like flow or box layouts.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} newly added child
 * @param vIndex {Integer} index of the child
 */
 qx.Proto.updateChildrenOnRemoveChild = function(vChild, vIndex) {}

/**
 * Move child within its parent to a new position.
 *  Needed by layouts where the children depend on each other, like flow or box layouts.
 *
 * Subclasses might implement this method
 *
 * @param vChild {qx.ui.core.Widget} newly added child
 * @param vIndex {Integer} new index of the child
 * @param vOldIndex {Integer} old index of the child
 */
qx.Proto.updateChildrenOnMoveChild = function(vChild, vIndex, vOldIndex) {}







/*
---------------------------------------------------------------------------
  [09] FLUSH LAYOUT QUEUES OF CHILDREN
---------------------------------------------------------------------------
*/

/**
 * Has full control of the order in which the registered
 * (or non-registered) children should be layouted.
 *
 * @param vChildrenQueue {Object}
 */
qx.Proto.flushChildrenQueue = function(vChildrenQueue)
{
  var vWidget = this.getWidget();

  for (var vHashCode in vChildrenQueue) {
    vWidget._layoutChild(vChildrenQueue[vHashCode]);
  }
}








/*
---------------------------------------------------------------------------
  [10] LAYOUT CHILD
---------------------------------------------------------------------------
*/

/**
 * Called from qx.ui.core.Parent. Its task is to apply the layout
 * (excluding border and padding) to the child.
 *
 * @param vChild {qx.ui.core.Widget} child to layout
 * @param vJobs {Set} layout changes to perform
 */
qx.Proto.layoutChild = function(vChild, vJobs) {}


/**
 * Apply min-/max-width to the child. Direct usage of stylesheet properties.
 * This is only possible in modern capable clients (i.e. excluding all current
 *  versions of Internet Explorer)
 *
 * @param vChild {qx.ui.core.Widget} child to layout
 * @param vJobs {Set} layout changes to perform
 */
qx.Proto.layoutChild_sizeLimitX = function(vChild, vJobs) {}

/**
 * Apply min-/max-height to the child. Direct usage of stylesheet properties.
 * This is only possible in modern capable clients (i.e. excluding all current
 *  versions of Internet Explorer)
 *
 * @param vChild {qx.ui.core.Widget} child to layout
 * @param vJobs {Set} layout changes to perform
 */
qx.Proto.layoutChild_sizeLimitY = function(vChild, vJobs) {}

if (qx.core.Client.getInstance().isMshtml())
{
  qx.Proto.layoutChild_sizeLimitX = qx.lang.Function.returnTrue;
  qx.Proto.layoutChild_sizeLimitY = qx.lang.Function.returnTrue;
}
else
{

  qx.Proto.layoutChild_sizeLimitX = function(vChild, vJobs)
  {
    if (vJobs.minWidth) {
      vChild._computedMinWidthTypeNull ? vChild._resetRuntimeMinWidth() : vChild._applyRuntimeMinWidth(vChild.getMinWidthValue());
    }
    else if (vJobs.initial && !vChild._computedMinWidthTypeNull) {
      vChild._applyRuntimeMinWidth(vChild.getMinWidthValue());
    }

    if (vJobs.maxWidth) {
      vChild._computedMaxWidthTypeNull ? vChild._resetRuntimeMaxWidth() : vChild._applyRuntimeMaxWidth(vChild.getMaxWidthValue());
    }
    else if (vJobs.initial && !vChild._computedMaxWidthTypeNull) {
      vChild._applyRuntimeMaxWidth(vChild.getMaxWidthValue());
    }
  }

  qx.Proto.layoutChild_sizeLimitY = function(vChild, vJobs)
  {
    if (vJobs.minHeight) {
      vChild._computedMinHeightTypeNull ? vChild._resetRuntimeMinHeight() : vChild._applyRuntimeMinHeight(vChild.getMinHeightValue());
    }
    else if (vJobs.initial && !vChild._computedMinHeightTypeNull) {
      vChild._applyRuntimeMinHeight(vChild.getMinHeightValue());
    }

    if (vJobs.maxHeight) {
      vChild._computedMaxHeightTypeNull ? vChild._resetRuntimeMaxHeight() : vChild._applyRuntimeMaxHeight(vChild.getMaxHeightValue());
    }
    else if (vJobs.initial && !vChild._computedMaxHeightTypeNull) {
      vChild._applyRuntimeMaxHeight(vChild.getMaxHeightValue());
    }
  }
}

/**
 * Apply the X margin values as pure stylesheet equivalent.
 *
 * @param vChild {qx.ui.core.Widget} child to layout
 * @param vJobs {Set} layout changes to perform
 */
qx.Proto.layoutChild_marginX = function(vChild, vJobs)
{
  if (vJobs.marginLeft || vJobs.initial)
  {
    var vValueLeft = vChild.getMarginLeft();
    vValueLeft != null ? vChild._applyRuntimeMarginLeft(vValueLeft) : vChild._resetRuntimeMarginLeft();
  }

  if (vJobs.marginRight || vJobs.initial)
  {
    var vValueRight = vChild.getMarginRight();
    vValueRight != null ? vChild._applyRuntimeMarginRight(vValueRight) : vChild._resetRuntimeMarginRight();
  }
}

/**
 * Apply the Y margin values as pure stylesheet equivalent.
 *
 * @param vChild {qx.ui.core.Widget} child to layout
 * @param vJobs {Set} layout changes to perform
 */
qx.Proto.layoutChild_marginY = function(vChild, vJobs)
{
  if (vJobs.marginTop || vJobs.initial)
  {
    var vValueTop = vChild.getMarginTop();
    vValueTop != null ? vChild._applyRuntimeMarginTop(vValueTop) : vChild._resetRuntimeMarginTop();
  }

  if (vJobs.marginBottom || vJobs.initial)
  {
    var vValueBottom = vChild.getMarginBottom();
    vValueBottom != null ? vChild._applyRuntimeMarginBottom(vValueBottom) : vChild._resetRuntimeMarginBottom();
  }
}

qx.Proto.layoutChild_sizeX_essentialWrapper = function(vChild, vJobs) {
  return vChild._isWidthEssential() ? this.layoutChild_sizeX(vChild, vJobs) : vChild._resetRuntimeWidth();
}

qx.Proto.layoutChild_sizeY_essentialWrapper = function(vChild, vJobs) {
  return vChild._isHeightEssential() ? this.layoutChild_sizeY(vChild, vJobs) : vChild._resetRuntimeHeight();
}






/*
---------------------------------------------------------------------------
  [11] DISPOSER
---------------------------------------------------------------------------
*/

/*!
  Dispose the layout implmentation and release the associated widget.
*/
qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  this._widget = null;

  qx.core.Object.prototype.dispose.call(this);
}
