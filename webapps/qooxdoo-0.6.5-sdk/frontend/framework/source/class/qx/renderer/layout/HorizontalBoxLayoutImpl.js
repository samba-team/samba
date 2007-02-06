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

#module(ui_basic)
#module(ui_layout)

************************************************************************ */

qx.OO.defineClass("qx.renderer.layout.HorizontalBoxLayoutImpl", qx.renderer.layout.LayoutImpl,
function(vWidget) {
  qx.renderer.layout.LayoutImpl.call(this, vWidget);
});

qx.OO.addProperty({ name : "enableFlexSupport", type : "boolean", defaultValue : true });

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
  [11] DISPOSER
*/




/*
---------------------------------------------------------------------------
  [01] COMPUTE BOX DIMENSIONS FOR AN INDIVIDUAL CHILD
---------------------------------------------------------------------------
*/

/*!
  Compute and return the box width of the given child.
*/
qx.Proto.computeChildBoxWidth = function(vChild) {
  return vChild.getWidthValue() || vChild._computeBoxWidthFallback();
}

/*!
  Compute and return the box height of the given child.
*/
qx.Proto.computeChildBoxHeight = function(vChild)
{
  if (this.getWidget().getStretchChildrenOrthogonalAxis() && vChild._computedHeightTypeNull && vChild.getAllowStretchY()) {
    return this.getWidget().getInnerHeight();
  }

  return vChild.getHeightValue() || vChild._computeBoxHeightFallback();
}

/*!
  Computes the width of all flexible children.
*/
qx.Proto.computeChildrenFlexWidth = function()
{
  if (this._childrenFlexWidthComputed || !this.getEnableFlexSupport()) {
    return;
  }

  this._childrenFlexWidthComputed = true;

  // this.debug("computeChildrenFlexWidth");

  var vWidget = this.getWidget();
  var vChildren = vWidget.getVisibleChildren();
  var vChildrenLength = vChildren.length;
  var vCurrentChild;
  var vFlexibleChildren = [];
  var vAvailWidth = vWidget.getInnerWidth();
  var vUsedWidth = vWidget.getSpacing() * (vChildrenLength-1);
  var vIterator;


  // *************************************************************
  // 1. Compute the sum of all static sized children and finding
  //    all flexible children.
  // *************************************************************
  for (vIterator=0; vIterator<vChildrenLength; vIterator++)
  {
    vCurrentChild = vChildren[vIterator];

    if (vCurrentChild._computedWidthTypeFlex)
    {
      vFlexibleChildren.push(vCurrentChild);

      if (vWidget._computedWidthTypeAuto) {
        vUsedWidth += vCurrentChild.getPreferredBoxWidth();
      }
    }
    else
    {
      vUsedWidth += vCurrentChild.getOuterWidth();
    }
  }

  // this.debug("Width: " + vUsedWidth + "/" + vAvailWidth);
  // this.debug("Flexible Count: " + vFlexibleChildren.length);


  // *************************************************************
  // 2. Compute the sum of all flexible children widths
  // *************************************************************
  var vRemainingWidth = vAvailWidth - vUsedWidth;
  var vFlexibleChildrenLength = vFlexibleChildren.length;
  var vPrioritySum = 0;

  for (vIterator=0; vIterator<vFlexibleChildrenLength; vIterator++) {
    vPrioritySum += vFlexibleChildren[vIterator]._computedWidthParsed;
  }


  // *************************************************************
  // 3. Calculating the size of each 'part'.
  // *************************************************************
  var vPartWidth = vRemainingWidth / vPrioritySum;


  if (!vWidget.getUseAdvancedFlexAllocation())
  {
    // *************************************************************
    // 4a. Computing the flex width value of each flexible child
    //     and add the width to the usedWidth, so that we can
    //     fix rounding problems later.
    // *************************************************************
    for (vIterator=0; vIterator<vFlexibleChildrenLength; vIterator++)
    {
      vCurrentChild = vFlexibleChildren[vIterator];

      vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthParsed * vPartWidth);
      vUsedWidth += vCurrentChild._computedWidthFlexValue;
    }
  }
  else
  {
    // *************************************************************
    // 4b. Calculating the diff. Which means respect the min/max
    //     width configuration in flex and store the higher/lower
    //     data in a diff.
    // *************************************************************

    var vAllocationDiff = 0;
    var vMinAllocationLoops, vFlexibleChildrenLength, vAdjust, vCurrentAllocationSum, vFactorSum, vComputedFlexibleWidth;

    for (vIterator=0; vIterator<vFlexibleChildrenLength; vIterator++)
    {
      vCurrentChild = vFlexibleChildren[vIterator];

      vComputedFlexibleWidth = vCurrentChild._computedWidthFlexValue = vCurrentChild._computedWidthParsed * vPartWidth;
      vAllocationDiff += vComputedFlexibleWidth - qx.lang.Number.limit(vComputedFlexibleWidth, vCurrentChild.getMinWidthValue(), vCurrentChild.getMaxWidthValue());
    }

    // Rounding diff
    vAllocationDiff = Math.round(vAllocationDiff);

    if (vAllocationDiff == 0)
    {
      // *************************************************************
      // 5a. If the diff is equal zero we must not do anything more
      //     and do nearly identical the same like in 4a. which means
      //     to round the calculated flex value and add it to the
      //     used width so we can fix rounding problems later.
      // *************************************************************

      // Rounding values and fixing rounding errors
      for (vIterator=0; vIterator<vFlexibleChildrenLength; vIterator++)
      {
        vCurrentChild = vFlexibleChildren[vIterator];

        vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthFlexValue);
        vUsedWidth += vCurrentChild._computedWidthFlexValue;
      }
    }
    else
    {
      // *************************************************************
      // 5b. Find maximum loops of each adjustable child to adjust
      //     the width until the min/max width limits are reached.
      // *************************************************************

      var vUp = vAllocationDiff > 0;
      for (vIterator=vFlexibleChildrenLength-1; vIterator>=0; vIterator--)
      {
        vCurrentChild = vFlexibleChildren[vIterator];

        if (vUp)
        {
          vAdjust = (vCurrentChild.getMaxWidthValue() || Infinity) - vCurrentChild._computedWidthFlexValue;

          if (vAdjust > 0)
          {
            vCurrentChild._allocationLoops = Math.floor(vAdjust / vCurrentChild._computedWidthParsed);
          }
          else
          {
            qx.lang.Array.removeAt(vFlexibleChildren, vIterator);

            vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthFlexValue);
            vUsedWidth += Math.round(vCurrentChild._computedWidthFlexValue + vAdjust);
          }
        }
        else
        {
          vAdjust = qx.util.Validation.isValidNumber(vCurrentChild.getMinWidthValue()) ? vCurrentChild._computedWidthFlexValue - vCurrentChild.getMinWidthValue() : vCurrentChild._computedWidthFlexValue;

          if (vAdjust > 0)
          {
            vCurrentChild._allocationLoops = Math.floor(vAdjust / vCurrentChild._computedWidthParsed);
          }
          else
          {
            qx.lang.Array.removeAt(vFlexibleChildren, vIterator);

            vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthFlexValue);
            vUsedWidth += Math.round(vCurrentChild._computedWidthFlexValue - vAdjust);
          }
        }
      }

      // *************************************************************
      // 6. Try to reallocate the width between flexible children
      //    so that the requirements through min/max limits
      //    are satisfied.
      // *************************************************************
      while (vAllocationDiff != 0 && vFlexibleChildrenLength > 0)
      {
        vFlexibleChildrenLength = vFlexibleChildren.length;
        vMinAllocationLoops = Infinity;
        vFactorSum = 0;

        // Find minimal loop amount
        for (vIterator=0; vIterator<vFlexibleChildrenLength; vIterator++)
        {
          vMinAllocationLoops = Math.min(vMinAllocationLoops, vFlexibleChildren[vIterator]._allocationLoops);
          vFactorSum += vFlexibleChildren[vIterator]._computedWidthParsed;
        }

        // Be sure that the adjustment is not bigger/smaller than diff
        vCurrentAllocationSum = Math.min(vFactorSum * vMinAllocationLoops, vAllocationDiff);

        // this.debug("Diff: " + vAllocationDiff);
        // this.debug("Min Loops: " + vMinAllocationLoops);
        // this.debug("Sum: " + vCurrentAllocationSum);
        // this.debug("Factor: " + vFactorSum);

        // Reducing diff by current sum
        vAllocationDiff -= vCurrentAllocationSum;

        // Adding sizes to children to adjust
        for (vIterator=vFlexibleChildrenLength-1; vIterator>=0; vIterator--)
        {
          vCurrentChild = vFlexibleChildren[vIterator];
          vCurrentChild._computedWidthFlexValue += vCurrentAllocationSum / vFactorSum * vCurrentChild._computedWidthParsed;

          if (vCurrentChild._allocationLoops == vMinAllocationLoops)
          {
            vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthFlexValue);

            vUsedWidth += vCurrentChild._computedWidthFlexValue;
            delete vCurrentChild._allocationLoops;
            qx.lang.Array.removeAt(vFlexibleChildren, vIterator);
          }
          else
          {
            if (vAllocationDiff == 0)
            {
              vCurrentChild._computedWidthFlexValue = Math.round(vCurrentChild._computedWidthFlexValue);
              vUsedWidth += vCurrentChild._computedWidthFlexValue;
              delete vCurrentChild._allocationLoops;
            }
            else
            {
              vCurrentChild._allocationLoops -= vMinAllocationLoops;
            }
          }
        }
      }
    }
  }

  // *************************************************************
  // 7. Fix rounding errors
  // *************************************************************
  vCurrentChild._computedWidthFlexValue += vAvailWidth - vUsedWidth;
}

qx.Proto.invalidateChildrenFlexWidth = function() {
  delete this._childrenFlexWidthComputed;
}







/*
---------------------------------------------------------------------------
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
---------------------------------------------------------------------------
*/

/*!
  Compute and return the width needed by all children of this widget
*/
qx.Proto.computeChildrenNeededWidth = function()
{
  var w = this.getWidget();
  return qx.renderer.layout.LayoutImpl.prototype.computeChildrenNeededWidth_sum.call(this) + ((w.getVisibleChildrenLength()-1) * w.getSpacing());
}






/*
---------------------------------------------------------------------------
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
---------------------------------------------------------------------------
*/

/*!
  Things to do and layout when any of the childs changes its outer width.
  Needed by layouts where the children depends on each-other, like flow- or box-layouts.
*/
qx.Proto.updateSelfOnChildOuterWidthChange = function(vChild)
{
  // if a childrens outer width changes we need to update our accumulated
  // width of all childrens (used for center or right alignments)
  this.getWidget()._invalidateAccumulatedChildrenOuterWidth();
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
  if (this.getWidget().getHorizontalChildrenAlign() == "center") {
    vChild.addToLayoutChanges("locationX");
  }

  // use variables here to be sure to call both methods.
  var vUpdatePercent = vChild._recomputePercentX();
  var vUpdateFlex = vChild._recomputeFlexX();

  // inform the caller if there were any notable changes occured
  return vUpdatePercent || vUpdateFlex;
}

/*!
  Actions that should be done if the inner height of the widget was changed.
  Normally this includes update to percent values and ranges.
*/
qx.Proto.updateChildOnInnerHeightChange = function(vChild)
{
  // use variables here to be sure to call both methods.
  var vUpdatePercent = vChild._recomputePercentY();
  var vUpdateStretch = vChild._recomputeStretchingY();

  // priority to childs internal alignment
  if ((vChild.getVerticalAlign() || this.getWidget().getVerticalChildrenAlign()) == "middle") {
    vChild.addToLayoutChanges("locationY");
  }

  // inform the caller if there were any notable changes occured
  return vUpdatePercent || vUpdateStretch;
}





/*
---------------------------------------------------------------------------
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
---------------------------------------------------------------------------
*/

/*!
  Invalidate and recompute things because of job in queue (before the rest of job handling will be executed).
*/
qx.Proto.updateSelfOnJobQueueFlush = function(vJobQueue)
{
  if (vJobQueue.addChild || vJobQueue.removeChild) {
    this.getWidget()._invalidateAccumulatedChildrenOuterWidth();
  }
}






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
  var vStretchX=false, vStretchY=false;
  var vWidget = this.getWidget();

  // switching the orientation need updates for stretching on both axis
  if (vQueue.orientation) {
    vStretchX = vStretchY = true;
  }

  // different updates depending from the current orientation (or the new one)
  if (vQueue.spacing || vQueue.orientation || vQueue.reverseChildrenOrder || vQueue.horizontalChildrenAlign) {
    vWidget._addChildrenToLayoutQueue("locationX");
  }

  if (vQueue.verticalChildrenAlign) {
    vWidget._addChildrenToLayoutQueue("locationY");
  }

  if (vQueue.stretchChildrenOrthogonalAxis) {
    vStretchY = true;
  }

  // if stretching should be reworked reset the previous one and add
  // a layout job to update the width respectively height.
  if (vStretchX)
  {
    vWidget._recomputeChildrenStretchingX();
    vWidget._addChildrenToLayoutQueue("width");
  }

  if (vStretchY)
  {
    vWidget._recomputeChildrenStretchingY();
    vWidget._addChildrenToLayoutQueue("height");
  }

  return true;
}





/*
---------------------------------------------------------------------------
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
---------------------------------------------------------------------------
*/

/*!
  This method combines calls of methods which should be done if a widget should be removed from the current layout.
  Needed by layouts where the children depends on each-other, like flow- or box-layouts.
*/
qx.Proto.updateChildrenOnRemoveChild = function(vChild, vIndex)
{
  var w=this.getWidget(), ch=w.getVisibleChildren(), chl=ch.length, chc, i=-1;

  // Fix index to be at the first flex child
  if (this.getEnableFlexSupport())
  {
    for (i=0; i<chl; i++)
    {
      chc = ch[i];
      if (chc.getHasFlexX())
      {
        vIndex = Math.min(vIndex, i);
        break;
      }
    }

    i=-1;
  }

  // Handle differently depending on layout mode
  switch(w.getLayoutMode())
  {
    case "right":
    case "left-reversed":
      while((chc=ch[++i]) && i<vIndex) {
        chc.addToLayoutChanges("locationX");
      }

      break;

    case "center":
    case "center-reversed":
      while(chc=ch[++i]) {
        chc.addToLayoutChanges("locationX");
      }

      break;

    default:
      i+=vIndex;
      while(chc=ch[++i]) {
        chc.addToLayoutChanges("locationX");
      }
  }
}

/*!
  This method combines calls of methods which should be done if a child should be moved
  inside the same parent to a new positions.
  Needed by layouts where the children depends on each-other, like flow- or box-layouts.
*/
qx.Proto.updateChildrenOnMoveChild = function(vChild, vIndex, vOldIndex)
{
  var vChildren = this.getWidget().getVisibleChildren();

  var vStart = Math.min(vIndex, vOldIndex);
  var vStop = Math.max(vIndex, vOldIndex)+1;

  for (var i=vStart; i<vStop; i++) {
    vChildren[i].addToLayoutChanges("locationX");
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
  var w=this.getWidget(), ch=w.getVisibleChildren(), chl=ch.length, chc, i;

  // This block is needed for flex handling and
  // will inform flex children if there was any
  // change to the other content
  if (this.getEnableFlexSupport())
  {
    this.invalidateChildrenFlexWidth();

    for (i=0; i<chl; i++)
    {
      chc = ch[i];
      if (chc.getHasFlexX())
      {
        chc._computedWidthValue = null;

        if (chc._recomputeBoxWidth())
        {
          chc._recomputeOuterWidth();
          chc._recomputeInnerWidth();
        }

        vChildrenQueue[chc.toHashCode()] = chc;
        chc._layoutChanges.width = true;
      }
    }
  }

  switch(w.getLayoutMode())
  {
    case "right":
    case "left-reversed":
      // find the last child which has a layout request
      for (var i=chl-1; i>=0 && !vChildrenQueue[ch[i].toHashCode()]; i--) {}

      // layout all children before this last child
      for (var j=0; j<=i; j++) {
        w._layoutChild(chc=ch[j]);
      }

      break;

    case "center":
    case "center-reversed":
      // re-layout all children
      i = -1;
      while(chc=ch[++i]) {
        w._layoutChild(chc);
      }

      break;

    default:
      // layout all childs from the first child
      // with an own layout request to the end
      i = -1;
      var changed=false;
      while(chc=ch[++i])
      {
        if (changed || vChildrenQueue[chc.toHashCode()])
        {
          w._layoutChild(chc);
          changed = true;
        }
      }
  }
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
  this.layoutChild_sizeX(vChild, vJobs);
  this.layoutChild_sizeY(vChild, vJobs);

  this.layoutChild_sizeLimitX(vChild, vJobs);
  this.layoutChild_sizeLimitY(vChild, vJobs);

  this.layoutChild_locationX(vChild, vJobs);
  this.layoutChild_locationY(vChild, vJobs);

  this.layoutChild_marginX(vChild, vJobs);
  this.layoutChild_marginY(vChild, vJobs);
}

if (qx.core.Client.getInstance().isMshtml() || qx.core.Client.getInstance().isOpera() || qx.core.Client.getInstance().isWebkit() )
{
  qx.Proto.layoutChild_sizeX = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.width || vJobs.minWidth || vJobs.maxWidth)
    {
      if (vChild._isWidthEssential() && (!vChild._computedWidthTypeNull || !vChild._computedMinWidthTypeNull || !vChild._computedMaxWidthTypeNull))
      {
        vChild._applyRuntimeWidth(vChild.getBoxWidth());
      }
      else
      {
        vChild._resetRuntimeWidth();
      }
    }
  }

  qx.Proto.layoutChild_sizeY = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.height || vJobs.minHeight || vJobs.maxHeight)
    {
      if ((vChild._isHeightEssential() && (!vChild._computedHeightTypeNull || !vChild._computedMinHeightTypeNull || !vChild._computedMaxHeightTypeNull)) || (vChild.getAllowStretchY() && this.getWidget().getStretchChildrenOrthogonalAxis()))
      {
        vChild._applyRuntimeHeight(vChild.getBoxHeight());
      }
      else
      {
        vChild._resetRuntimeHeight();
      }
    }
  }
}
else
{
  qx.Proto.layoutChild_sizeX = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.width)
    {
      if (vChild._isWidthEssential() && !vChild._computedWidthTypeNull)
      {
        vChild._applyRuntimeWidth(vChild.getWidthValue());
      }
      else
      {
        vChild._resetRuntimeWidth();
      }
    }
  }

  qx.Proto.layoutChild_sizeY = function(vChild, vJobs)
  {
    if (vJobs.initial || vJobs.height)
    {
      if (vChild._isHeightEssential() && !vChild._computedHeightTypeNull)
      {
        vChild._applyRuntimeHeight(vChild.getHeightValue());
      }
      else
      {
        vChild._resetRuntimeHeight();
      }
    }
  }
}

qx.Proto.layoutChild_locationX = function(vChild, vJobs)
{
  var vWidget = this.getWidget();

  // handle first child
  if (vWidget.getFirstVisibleChild() == vChild)
  {
    switch(vWidget.getLayoutMode())
    {
      case "right":
      case "left-reversed":
        var vPos = vWidget.getPaddingRight() + vWidget.getAccumulatedChildrenOuterWidth() - vChild.getOuterWidth();
        break;

      case "center":
      case "center-reversed":
        var vPos = vWidget.getPaddingLeft() + Math.round((vWidget.getInnerWidth() - vWidget.getAccumulatedChildrenOuterWidth()) / 2);
        break;

      default:
        var vPos = vWidget.getPaddingLeft();
    }
  }

  // handle any following child
  else
  {
    var vPrev = vChild.getPreviousVisibleSibling();

    switch(vWidget.getLayoutMode())
    {
      case "right":
      case "left-reversed":
        var vPos = vPrev._cachedLocationHorizontal - vChild.getOuterWidth() - vWidget.getSpacing();
        break;

      default:
        var vPos = vPrev._cachedLocationHorizontal + vPrev.getOuterWidth() + vWidget.getSpacing();
    }
  }

  // store for next sibling
  vChild._cachedLocationHorizontal = vPos;

  // apply styles
  switch(vWidget.getLayoutMode())
  {
    case "right":
    case "right-reversed":
    case "center-reversed":
      // add relative positions (like 'position:relative' in css)
      vPos += !vChild._computedRightTypeNull ? vChild.getRightValue() : !vChild._computedLeftTypeNull ? -(vChild.getLeftValue()) : 0;

      vChild._resetRuntimeLeft();
      vChild._applyRuntimeRight(vPos);
      break;

    default:
      // add relative positions (like 'position:relative' in css)
      vPos += !vChild._computedLeftTypeNull ? vChild.getLeftValue() : !vChild._computedRightTypeNull ? -(vChild.getRightValue()) : 0;

      vChild._resetRuntimeRight();
      vChild._applyRuntimeLeft(vPos);
  }
}

qx.Proto.layoutChild_locationY = function(vChild, vJobs)
{
  var vWidget = this.getWidget();

  // special stretching support
  if (qx.core.Client.getInstance().isGecko() && vChild.getAllowStretchY() && vWidget.getStretchChildrenOrthogonalAxis() && vChild._computedHeightTypeNull)
  {
    vChild._applyRuntimeTop(vWidget.getPaddingTop() || 0);
    vChild._applyRuntimeBottom(vWidget.getPaddingBottom() || 0);

    return;
  }

  // priority to childs internal alignment
  var vAlign = vChild.getVerticalAlign() || vWidget.getVerticalChildrenAlign();

  // handle middle alignment
  var vPos = vAlign == "middle" ? Math.round((vWidget.getInnerHeight() - vChild.getOuterHeight()) / 2) : 0;

  // the bottom alignment use the real 'bottom' styleproperty to
  // use the best available method in modern browsers
  if (vAlign == "bottom")
  {
    // add parent padding
    vPos += vWidget.getPaddingBottom();

    // relative positions (like 'position:relative' in css)
    if (!vChild._computedBottomTypeNull) {
      vPos += vChild.getBottomValue();
    }
    else if (!vChild._computedTopTypeNull) {
      vPos -= vChild.getTopValue();
    }

    // apply styles
    vChild._resetRuntimeTop();
    vChild._applyRuntimeBottom(vPos);
  }
  else
  {
    // add parent padding
    vPos += vWidget.getPaddingTop();

    // relative positions (like 'position:relative' in css)
    if (!vChild._computedTopTypeNull) {
      vPos += vChild.getTopValue();
    }
    else if (!vChild._computedBottomTypeNull) {
      vPos -= vChild.getBottomValue();
    }

    // apply styles
    vChild._resetRuntimeBottom();
    vChild._applyRuntimeTop(vPos);
  }
}
