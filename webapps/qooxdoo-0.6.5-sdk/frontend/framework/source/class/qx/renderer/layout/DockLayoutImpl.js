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

#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.renderer.layout.DockLayoutImpl", qx.renderer.layout.LayoutImpl,
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
  [02] COMPUTE NEEDED DIMENSIONS FOR AN INDIVIDUAL CHILD
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
  [11] DISPOSER
*/




/*
---------------------------------------------------------------------------
  [00] ADDITIONAL GLOBAL DATA AND METHODS
---------------------------------------------------------------------------
*/

qx.renderer.layout.DockLayoutImpl.METHOD_LOCATION = "layoutChild_location_";

qx.renderer.layout.DockLayoutImpl._childRanking = {
  vertical : function(c) { return c.getVerticalAlign() ? 1e6 : c.getHorizontalAlign() ? 2e6 : 3e6; },
  horizontal : function(c) { return c.getHorizontalAlign() ? 1e6 : c.getVerticalAlign() ? 2e6 : 3e6; },
  ordered : function(c) { return c.getHorizontalAlign() || c.getVerticalAlign() ? 1e6 : 2e6; }
}

qx.renderer.layout.DockLayoutImpl._childCheck =
{
  common : function(vChild) {
    if (!(vChild._computedLeftTypeNull && vChild._computedRightTypeNull && vChild._computedTopTypeNull && vChild._computedBottomTypeNull)) {
      throw new Error("qx.renderer.layout.DockLayoutImpl: It is not allowed to define any location values for children: " + vChild + "!");
    }
  },

  horizontal : function(vChild)
  {
    if (!(vChild._computedMinHeightTypeNull && vChild._computedHeightTypeNull && vChild._computedMaxHeightTypeNull)) {
      throw new Error("qx.renderer.layout.DockLayoutImpl: It is not allowed to define any vertical dimension for 'horizontal' placed children: " + vChild + "!");
    }
  },

  vertical : function(vChild)
  {
    if (!(vChild._computedMinWidthTypeNull && vChild._computedWidthTypeNull && vChild._computedMaxWidthTypeNull)) {
      throw new Error("qx.renderer.layout.DockLayoutImpl: It is not allowed to define any horizontal dimension for 'vertical' placed children: " + vChild + "!");
    }
  },

  "default" : function(vChild)
  {
    qx.renderer.layout.DockLayoutImpl._childCheck.horizontal(vChild);
    qx.renderer.layout.DockLayoutImpl._childCheck.vertical(vChild);
  }
}







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
  if (this.getChildAlignMode(vChild) == "horizontal") {
    return vChild.getWidthValue() || vChild._computeBoxWidthFallback();
  }

  return this.getWidget().getInnerWidth() - this._lastLeft - this._lastRight;
}

/*!
  Compute and return the box height of the given child
*/
qx.Proto.computeChildBoxHeight = function(vChild)
{
  if (this.getChildAlignMode(vChild) == "vertical") {
    return vChild.getHeightValue() || vChild._computeBoxHeightFallback();
  }

  return this.getWidget().getInnerHeight() - this._lastTop - this._lastBottom;
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
  vChild._recomputePercentX();
  vChild.addToLayoutChanges("location");

  // inform the caller if there were any notable changes occured
  return true;
}

/*!
  Actions that should be done if the inner height of the widget was changed.
  Normally this includes update to percent values and ranges.
*/
qx.Proto.updateChildOnInnerHeightChange = function(vChild)
{
  vChild._recomputePercentY();
  vChild.addToLayoutChanges("location");

  // inform the caller if there were any notable changes occured
  return true;
}





/*
---------------------------------------------------------------------------
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
---------------------------------------------------------------------------
*/

/*!
  Invalidate and recompute things because of job in queue (before the rest of job handling will be executed).
*/
qx.Proto.updateSelfOnJobQueueFlush = qx.lang.Function.returnFalse;







/*
---------------------------------------------------------------------------
  [07] UPDATE CHILDREN ON JOB QUEUE FLUSH
---------------------------------------------------------------------------
*/

/*!
  Updates children on special jobs
*/
qx.Proto.updateChildrenOnJobQueueFlush = function(vQueue)
{
  if (vQueue.mode || vQueue.addChild || vQueue.removeChild) {
    this.getWidget()._addChildrenToLayoutQueue("location");
  }
}









/*
---------------------------------------------------------------------------
  [09] FLUSH LAYOUT QUEUES OF CHILDREN
---------------------------------------------------------------------------
*/

/*!
  This method have full control of the order in which the
  registered (or also non-registered) children should be
  layouted on the horizontal axis.
*/
qx.Proto.flushChildrenQueue = function(vChildrenQueue)
{
  var vWidget=this.getWidget(), vChildren=vWidget.getVisibleChildren(), vChildrenLength=vChildren.length, vMode=vWidget.getMode();

  // reset layout
  this._lastLeft = this._lastRight = this._lastTop = this._lastBottom = 0;

  // sorting children
  var vRankImpl = qx.renderer.layout.DockLayoutImpl._childRanking[vMode];
  var vOrderedChildren = qx.lang.Array.copy(vChildren).sort(function(c1, c2) {
    return (vRankImpl(c1) + vChildren.indexOf(c1)) - (vRankImpl(c2) + vChildren.indexOf(c2));
  });

  // flushing children
  for (var i=0; i<vChildrenLength; i++) {
    vWidget._layoutChild(vOrderedChildren[i]);
  }
}

qx.Proto.getChildAlign = function(vChild) {
  return vChild.getVerticalAlign() || vChild.getHorizontalAlign() || "default";
}

qx.Proto.getChildAlignMode = function(vChild) {
  return vChild.getVerticalAlign() ? "vertical" : vChild.getHorizontalAlign() ? "horizontal" : "default";
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
  qx.renderer.layout.DockLayoutImpl._childCheck.common(vChild);
  qx.renderer.layout.DockLayoutImpl._childCheck[this.getChildAlignMode(vChild)](vChild);

  this.layoutChild_sizeX_essentialWrapper(vChild, vJobs);
  this.layoutChild_sizeY_essentialWrapper(vChild, vJobs);

  this.layoutChild_sizeLimitX(vChild, vJobs);
  this.layoutChild_sizeLimitY(vChild, vJobs);

  this[qx.renderer.layout.DockLayoutImpl.METHOD_LOCATION + this.getChildAlign(vChild)](vChild, vJobs);
}

qx.Proto.layoutChild_location_top = function(vChild, vJobs)
{
  vChild._applyRuntimeTop(this._lastTop);
  vChild._applyRuntimeLeft(this._lastLeft);

  this.layoutChild_location_horizontal(vChild);

  this._lastTop += vChild.getBoxHeight();
}

qx.Proto.layoutChild_location_left = function(vChild, vJobs)
{
  vChild._applyRuntimeLeft(this._lastLeft);
  vChild._applyRuntimeTop(this._lastTop);

  this.layoutChild_location_vertical(vChild);

  this._lastLeft += vChild.getBoxWidth();
}







if (qx.core.Client.getInstance().isMshtml() || qx.core.Client.getInstance().isOpera())
{
  qx.Proto._applyComputedWidth = function(vChild)
  {
    // direct recompute (need to be done, while layouting as the
    // _last* variable changes during layout process)
    vChild._recomputeBoxWidth();

    // wrong: simple invalidates are enough here
    // correct: needs recompute to inform children (to update centering for example)
    vChild._recomputeOuterWidth();
    vChild._recomputeInnerWidth();

    // apply calculated width
    vChild._applyRuntimeWidth(vChild.getBoxWidth());
  }

  qx.Proto._applyComputedHeight = function(vChild)
  {
    // direct recompute (need to be done, while layouting as the
    // _last* variable changes during layout process)
    vChild._recomputeBoxHeight();

    // wrong: simple invalidates are enough here
    // correct: needs recompute to inform children (to update centering for example)
    vChild._recomputeOuterHeight();
    vChild._recomputeInnerHeight();

    // apply calculated height
    vChild._applyRuntimeHeight(vChild.getBoxHeight());
  }

  qx.Proto.layoutChild_sizeX = function(vChild, vJobs)
  {
    // We need to respect all dimension properties on the horizontal axis in internet explorer to set the 'width' style
    if (vJobs.initial || vJobs.width || vJobs.minWidth || vJobs.maxWidth) {
      vChild._computedWidthTypeNull && vChild._computedMinWidthTypeNull && vChild._computedMaxWidthTypeNull ? vChild._resetRuntimeWidth() : vChild._applyRuntimeWidth(vChild.getBoxWidth());
    }
  }

  qx.Proto.layoutChild_sizeY = function(vChild, vJobs)
  {
    // We need to respect all dimension properties on the vertical axis in internet explorer to set the 'height' style
    if (vJobs.initial || vJobs.height || vJobs.minHeight || vJobs.maxHeight) {
      vChild._computedHeightTypeNull && vChild._computedMinHeightTypeNull && vChild._computedMaxHeightTypeNull ? vChild._resetRuntimeHeight() : vChild._applyRuntimeHeight(vChild.getBoxHeight());
    }
  }

  qx.Proto.layoutChild_location_horizontal = function(vChild) {
    this._applyComputedWidth(vChild);
  }

  qx.Proto.layoutChild_location_vertical = function(vChild) {
    this._applyComputedHeight(vChild);
  }

  qx.Proto.layoutChild_location_right = function(vChild, vJobs)
  {
    vChild._applyRuntimeLeft(this.getWidget().getInnerWidth() - this._lastRight - vChild.getBoxWidth());
    vChild._applyRuntimeTop(this._lastTop);

    this.layoutChild_location_vertical(vChild);

    this._lastRight += vChild.getBoxWidth();
  }

  qx.Proto.layoutChild_location_bottom = function(vChild, vJobs)
  {
    vChild._applyRuntimeTop(this.getWidget().getInnerHeight() - this._lastBottom - vChild.getBoxHeight());
    vChild._applyRuntimeLeft(this._lastLeft);

    this.layoutChild_location_horizontal(vChild);

    this._lastBottom += vChild.getBoxHeight();
  }

  qx.Proto.layoutChild_location_default = function(vChild, vJobs)
  {
    var vWidget = this.getWidget();

    vChild._resetRuntimeRight();
    vChild._resetRuntimeBottom();

    vChild._applyRuntimeTop(this._lastTop);
    vChild._applyRuntimeLeft(this._lastLeft);

    this._applyComputedWidth(vChild);
    this._applyComputedHeight(vChild);
  }
}
else
{
  qx.Proto._applyComputedWidth = function(vChild)
  {
    // direct recompute (need to be done, while layouting as the
    // _last* variable changes during layout process)
    vChild._recomputeBoxWidth();

    // wrong: simple invalidates are enough here
    // correct: needs recompute to inform children (to update centering for example)
    vChild._recomputeOuterWidth();
    vChild._recomputeInnerWidth();
  }

  qx.Proto._applyComputedHeight = function(vChild)
  {
    // direct recompute (need to be done, while layouting as the
    // _last* variable changes during layout process)
    vChild._recomputeBoxHeight();

    // wrong: simple invalidates are enough here
    // correct: needs recompute to inform children (to update centering for example)
    vChild._recomputeOuterHeight();
    vChild._recomputeInnerHeight();
  }

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

  qx.Proto.layoutChild_location_horizontal = function(vChild)
  {
    this._applyComputedWidth(vChild);
    vChild._applyRuntimeRight(this._lastRight);
  }

  qx.Proto.layoutChild_location_vertical = function(vChild)
  {
    this._applyComputedHeight(vChild);
    vChild._applyRuntimeBottom(this._lastBottom);
  }

  qx.Proto.layoutChild_location_right = function(vChild, vJobs)
  {
    vChild._applyRuntimeRight(this._lastRight);
    vChild._applyRuntimeTop(this._lastTop);

    this.layoutChild_location_vertical(vChild);

    this._lastRight += vChild.getBoxWidth();
  }

  qx.Proto.layoutChild_location_bottom = function(vChild, vJobs)
  {
    vChild._applyRuntimeBottom(this._lastBottom);
    vChild._applyRuntimeLeft(this._lastLeft);

    this.layoutChild_location_horizontal(vChild);

    this._lastBottom += vChild.getBoxHeight();
  }

  qx.Proto.layoutChild_location_default = function(vChild, vJobs)
  {
    vChild._resetRuntimeWidth();
    vChild._resetRuntimeHeight();

    vChild._applyRuntimeTop(this._lastTop);
    vChild._applyRuntimeRight(this._lastRight);
    vChild._applyRuntimeBottom(this._lastBottom);
    vChild._applyRuntimeLeft(this._lastLeft);

    this._applyComputedWidth(vChild);
    this._applyComputedHeight(vChild);
  }
}
