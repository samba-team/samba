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
#optional(qx.event.handler.FocusHandler)
#optional(qx.manager.object.ToolTipManager)
#optional(qx.manager.object.PopupManager)
#optional(qx.dom.ElementFromPoint)

************************************************************************ */

qx.OO.defineClass("qx.ui.core.Parent", qx.ui.core.Widget,
function()
{
  if (this.classname == qx.ui.core.Parent.ABSTRACT_CLASS) {
    throw new Error("Please omit the usage of qx.ui.core.Parent directly. Choose between any widget which inherits from qx.ui.core.Parent and so comes with a layout implementation!");
  }

  qx.ui.core.Widget.call(this);

  // Contains all children
  this._children = [];

  // Create instanceof layout implementation
  this._layoutImpl = this._createLayoutImpl();
});

qx.ui.core.Parent.ABSTRACT_CLASS = "qx.ui.core.Parent";




/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

/*!
  Individual focus handler for all child elements.
*/
qx.OO.addProperty({ name : "focusHandler", type : "object", instance : "qx.event.handler.FocusHandler" });

/*!
  The current active child.
*/
qx.OO.addProperty({ name : "activeChild", type : "object", instance : "qx.ui.core.Widget" });

/*!
  The current focused child.
*/
qx.OO.addProperty({ name : "focusedChild", type : "object", instance : "qx.ui.core.Widget" });





/*
---------------------------------------------------------------------------
  CACHED PRIVATE PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addCachedProperty({ name : "visibleChildren", defaultValue : null });






/*
---------------------------------------------------------------------------
  FOCUS HANDLING
---------------------------------------------------------------------------
*/

qx.Proto.isFocusRoot = function() {
  return this.getFocusHandler() != null;
}

qx.Proto.getFocusRoot = function()
{
  if (this.isFocusRoot()) {
    return this;
  }

  if(this._hasParent) {
    return this.getParent().getFocusRoot();
  }

  return null;
}

qx.Proto.activateFocusRoot = function() {
  this.setFocusHandler(new qx.event.handler.FocusHandler(this));
}

qx.Proto._onfocuskeyevent = function(e) {
  this.getFocusHandler()._onkeyevent(this, e);
}

qx.Proto._modifyFocusHandler = function(propValue, propOldValue, propData)
{
  if (propValue)
  {
    // Add Key Handler
    this.addEventListener("keydown", this._onfocuskeyevent);
    this.addEventListener("keypress", this._onfocuskeyevent);

    // Activate focus handling (but keep already configured tabIndex)
    if (this.getTabIndex() < 1) {
      this.setTabIndex(1);
    }

    // But hide the focus outline
    this.setHideFocus(true);

    // Make myself the default
    this.setActiveChild(this);
  }
  else
  {
    // Remove Key Handler
    this.removeEventListener("keydown", this._onfocuskeyevent);
    this.removeEventListener("keypress", this._onfocuskeyevent);

    // Deactivate focus handling
    this.setTabIndex(-1);

    // Don't hide focus outline
    this.setHideFocus(false);
  }

  return true;
}

qx.Proto._modifyFocusedChild = function(propValue, propOldValue, propData)
{
  // this.debug("FocusedChild: " + propValue);

  var vFocusValid = qx.util.Validation.isValidObject(propValue);
  var vBlurValid = qx.util.Validation.isValidObject(propOldValue);

  if (qx.OO.isAvailable("qx.manager.object.PopupManager") && vFocusValid)
  {
    var vMgr = qx.manager.object.PopupManager.getInstance();
    if (vMgr) {
      vMgr.update(propValue);
    }
  }

  if (vBlurValid)
  {
    // Dispatch FocusOut
    if (propOldValue.hasEventListeners("focusout"))
    {
      var vEventObject = new qx.event.type.FocusEvent("focusout", propOldValue);

      if (vFocusValid) {
        vEventObject.setRelatedTarget(propValue);
      }

      propOldValue.dispatchEvent(vEventObject);
      vEventObject.dispose();
    }
  }

  if (vFocusValid)
  {
    if (propValue.hasEventListeners("focusin"))
    {
      // Dispatch FocusIn
      var vEventObject = new qx.event.type.FocusEvent("focusin", propValue);

      if (vBlurValid) {
        vEventObject.setRelatedTarget(propOldValue);
      }

      propValue.dispatchEvent(vEventObject);
      vEventObject.dispose();
    }
  }

  if (vBlurValid)
  {
    if (this.getActiveChild() == propOldValue) {
      this.setActiveChild(null);
    }

    propOldValue.setFocused(false);

    // Dispatch Blur
    var vEventObject = new qx.event.type.FocusEvent("blur", propOldValue);

    if (vFocusValid) {
      vEventObject.setRelatedTarget(propValue);
    }

    propOldValue.dispatchEvent(vEventObject);

    if (qx.OO.isAvailable("qx.manager.object.ToolTipManager"))
    {
      var vMgr = qx.manager.object.ToolTipManager.getInstance();
      if (vMgr) {
        vMgr.handleBlur(vEventObject);
      }
    }

    vEventObject.dispose();
  }

  if (vFocusValid)
  {
    this.setActiveChild(propValue);
    propValue.setFocused(true);
    qx.event.handler.EventHandler.getInstance().setFocusRoot(this);

    // Dispatch Focus
    var vEventObject = new qx.event.type.FocusEvent("focus", propValue);

    if (vBlurValid) {
      vEventObject.setRelatedTarget(propOldValue);
    }

    propValue.dispatchEvent(vEventObject);

    if (qx.OO.isAvailable("qx.manager.object.ToolTipManager"))
    {
      var vMgr = qx.manager.object.ToolTipManager.getInstance();
      if (vMgr) {
        vMgr.handleFocus(vEventObject);
      }
    }

    vEventObject.dispose();
  }

  // Flush Queues
  // Do we really need this?
  // qx.ui.core.Widget.flushGlobalQueues();

  return true;
}





/*
---------------------------------------------------------------------------
  LAYOUT IMPLEMENTATION
---------------------------------------------------------------------------
*/

qx.Proto._layoutImpl = null;

qx.Proto._createLayoutImpl = function() {
  return null;
}

qx.Proto.getLayoutImpl = function() {
  return this._layoutImpl;
}







/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: MANAGE ALL
---------------------------------------------------------------------------
*/

/*!
  Return the array of all children
*/
qx.Proto.getChildren = function() {
  return this._children;
}

/*!
  Get children count
*/
qx.Proto.getChildrenLength = function() {
  return this.getChildren().length;
}

/*!
  Check if the widget has a children
*/
qx.Proto.hasChildren = function() {
  return this.getChildrenLength() > 0;
}

/*!
  Check if there are any childrens inside
*/
qx.Proto.isEmpty = function() {
  return this.getChildrenLength() == 0;
}

/*!
  Get the position of a children.
*/
qx.Proto.indexOf = function(vChild) {
  return this.getChildren().indexOf(vChild);
}

/*!
Check if the given qx.ui.core.Widget is a children.

#param des[qx.ui.core.Widget]: The widget which should be checked.
*/
qx.Proto.contains = function(vWidget)
{
  switch(vWidget)
  {
    case null:
      return false;

    case this:
      return true;

    default:
      // try the next parent of the widget (recursive until found)
      return this.contains(vWidget.getParent());
  }
}






/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: MANAGE VISIBLE ONES

  uses a cached private property
---------------------------------------------------------------------------
*/

/*!
  Return the array of all visible children
  (which are configured as visible=true)
*/
qx.Proto._computeVisibleChildren = function()
{
  var vVisible = [];
  var vChildren = this.getChildren();
  var vLength = vChildren.length;

  for (var i=0; i<vLength; i++)
  {
    var vChild = vChildren[i];
    if (vChild._isDisplayable) {
      vVisible.push(vChild);
    }
  }

  return vVisible;
}

/*!
  Get length of visible children
*/
qx.Proto.getVisibleChildrenLength = function() {
  return this.getVisibleChildren().length;
}

/*!
  Check if the widget has any visible children
*/
qx.Proto.hasVisibleChildren = function() {
  return this.getVisibleChildrenLength() > 0;
}

/*!
  Check if there are any visible childrens inside
*/
qx.Proto.isVisibleEmpty = function() {
  return this.getVisibleChildrenLength() == 0;
}






/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: ADD
---------------------------------------------------------------------------
*/

/*!
  Add/Append another widget. Allows to add multiple at
  one, a parameter could be a widget.
*/
qx.Proto.add = function()
{
  var vWidget;

  for (var i=0, l=arguments.length; i<l; i++)
  {
    vWidget = arguments[i];

    if (!(vWidget instanceof qx.ui.core.Parent) && !(vWidget instanceof qx.ui.basic.Terminator))
    {
      throw new Error("Invalid Widget: " + vWidget);
    }
    else
    {
      vWidget.setParent(this);
    }
  }

  return this;
}

qx.Proto.addAt = function(vChild, vIndex)
{
  if (qx.util.Validation.isInvalidNumber(vIndex) || vIndex == -1) {
    throw new Error("Not a valid index for addAt(): " + vIndex);
  }

  if (vChild.getParent() == this)
  {
    var vChildren = this.getChildren();
    var vOldIndex = vChildren.indexOf(vChild);

    if (vOldIndex != vIndex)
    {
      if (vOldIndex != -1) {
        qx.lang.Array.removeAt(vChildren, vOldIndex);
      }

      qx.lang.Array.insertAt(vChildren, vChild, vIndex);

      if (this._initialLayoutDone)
      {
        this._invalidateVisibleChildren();
        this.getLayoutImpl().updateChildrenOnMoveChild(vChild, vIndex, vOldIndex);
      }
    }
  }
  else
  {
    vChild._insertIndex = vIndex;
    vChild.setParent(this);
  }
}

qx.Proto.addAtBegin = function(vChild) {
  return this.addAt(vChild, 0);
}

qx.Proto.addAtEnd = function(vChild)
{
  // we need to fix here, when the child is already inside myself, but
  // want to change its position
  var vLength = this.getChildrenLength();
  return this.addAt(vChild, vChild.getParent() == this ? vLength - 1 : vLength);
}

/*!
  Add a widget before another already inserted child
*/
qx.Proto.addBefore = function(vChild, vBefore)
{
  var vChildren = this.getChildren();
  var vTargetIndex = vChildren.indexOf(vBefore);

  if (vTargetIndex == -1) {
    throw new Error("Child to add before: " + vBefore + " is not inside this parent.");
  }

  var vSourceIndex = vChildren.indexOf(vChild);

  if (vSourceIndex == -1 || vSourceIndex > vTargetIndex) {
    vTargetIndex++;
  }

  return this.addAt(vChild, Math.max(0, vTargetIndex-1));
}

/*!
  Add a widget after another already inserted child
*/
qx.Proto.addAfter = function(vChild, vAfter)
{
  var vChildren = this.getChildren();
  var vTargetIndex = vChildren.indexOf(vAfter);

  if (vTargetIndex == -1) {
    throw new Error("Child to add after: " + vAfter + " is not inside this parent.");
  }

  var vSourceIndex = vChildren.indexOf(vChild);

  if (vSourceIndex != -1 && vSourceIndex < vTargetIndex) {
    vTargetIndex--;
  }

  return this.addAt(vChild, Math.min(vChildren.length, vTargetIndex+1));
}







/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: REMOVE
---------------------------------------------------------------------------
*/

/*!
  Remove one or multiple childrens.
*/
qx.Proto.remove = function()
{
  var vWidget;

  for (var i=0, l=arguments.length; i<l; i++)
  {
    vWidget = arguments[i];

    if (!(vWidget instanceof qx.ui.core.Parent) && !(vWidget instanceof qx.ui.basic.Terminator))
    {
      throw new Error("Invalid Widget: " + vWidget);
    }
    else if (vWidget.getParent() == this)
    {
      vWidget.setParent(null);
    }
  }
}

qx.Proto.removeAt = function(vIndex)
{
  var vChild = this.getChildren()[vIndex];

  if (vChild)
  {
    delete vChild._insertIndex;

    vChild.setParent(null);
  }
}

/*!
  Remove all childrens.
*/
qx.Proto.removeAll = function()
{
  var cs = this.getChildren();
  var co = cs[0];

  while (co)
  {
    this.remove(co);
    co = cs[0];
  }
}






/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: FIRST CHILD
---------------------------------------------------------------------------
*/

qx.Proto.getFirstChild = function() {
  return qx.lang.Array.getFirst(this.getChildren());
}

qx.Proto.getFirstVisibleChild = function() {
  return qx.lang.Array.getFirst(this.getVisibleChildren());
}

qx.Proto.getFirstActiveChild = function(vIgnoreClasses) {
  return qx.ui.core.Widget.getActiveSiblingHelper(null, this, 1, vIgnoreClasses, "first");
}






/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: LAST CHILD
---------------------------------------------------------------------------
*/

qx.Proto.getLastChild = function() {
  return qx.lang.Array.getLast(this.getChildren());
}

qx.Proto.getLastVisibleChild = function() {
  return qx.lang.Array.getLast(this.getVisibleChildren());
}

qx.Proto.getLastActiveChild = function(vIgnoreClasses) {
  return qx.ui.core.Widget.getActiveSiblingHelper(null, this, -1, vIgnoreClasses, "last");
}






/*
---------------------------------------------------------------------------
  CHILDREN MANAGMENT: LOOP UTILS
---------------------------------------------------------------------------
*/

qx.Proto.forEachChild = function(vFunc)
{
  var ch=this.getChildren(), chc, i=-1;
  while(chc=ch[++i]) {
    vFunc.call(chc, i);
  }
}

qx.Proto.forEachVisibleChild = function(vFunc)
{
  var ch=this.getVisibleChildren(), chc, i=-1;
  while(chc=ch[++i]) {
    vFunc.call(chc, i);
  }
}






/*
---------------------------------------------------------------------------
  APPEAR/DISAPPEAR MESSAGES FOR CHILDREN
---------------------------------------------------------------------------
*/

qx.Proto._beforeAppear = function()
{
  qx.ui.core.Widget.prototype._beforeAppear.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._beforeAppear();
    }
  });
}

qx.Proto._afterAppear = function()
{
  qx.ui.core.Widget.prototype._afterAppear.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._afterAppear();
    }
  });
}

qx.Proto._beforeDisappear = function()
{
  qx.ui.core.Widget.prototype._beforeDisappear.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._beforeDisappear();
    }
  });
}

qx.Proto._afterDisappear = function()
{
  qx.ui.core.Widget.prototype._afterDisappear.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._afterDisappear();
    }
  });
}







/*
---------------------------------------------------------------------------
  INSERTDOM/REMOVEDOM MESSAGES FOR CHILDREN
---------------------------------------------------------------------------
*/

qx.Proto._beforeInsertDom = function()
{
  qx.ui.core.Widget.prototype._beforeInsertDom.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._beforeInsertDom();
    }
  });
}

qx.Proto._afterInsertDom = function()
{
  qx.ui.core.Widget.prototype._afterInsertDom.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._afterInsertDom();
    }
  });
}

qx.Proto._beforeRemoveDom = function()
{
  qx.ui.core.Widget.prototype._beforeRemoveDom.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._beforeRemoveDom();
    }
  });
}

qx.Proto._afterRemoveDom = function()
{
  qx.ui.core.Widget.prototype._afterRemoveDom.call(this);

  this.forEachVisibleChild(function() {
    if (this.isAppearRelevant()) {
      this._afterRemoveDom();
    }
  });
}







/*
---------------------------------------------------------------------------
  DISPLAYBLE HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._handleDisplayableCustom = function(vDisplayable, vParent, vHint)
{
  this.forEachChild(function() {
    this._handleDisplayable();
  });
}







/*
---------------------------------------------------------------------------
  STATE QUEUE
---------------------------------------------------------------------------
*/

qx.Proto._addChildrenToStateQueue = function()
{
  this.forEachVisibleChild(function() {
    this.addToStateQueue();
  });
}

qx.Proto.recursiveAddToStateQueue = function()
{
  this.addToStateQueue();

  this.forEachVisibleChild(function() {
    this.recursiveAddToStateQueue();
  });
}

qx.Proto._recursiveAppearanceThemeUpdate = function(vNewAppearanceTheme, vOldAppearanceTheme)
{
  qx.ui.core.Widget.prototype._recursiveAppearanceThemeUpdate.call(this, vNewAppearanceTheme, vOldAppearanceTheme);

  this.forEachVisibleChild(function() {
    this._recursiveAppearanceThemeUpdate(vNewAppearanceTheme, vOldAppearanceTheme);
  });
}






/*
---------------------------------------------------------------------------
  CHILDREN QUEUE
---------------------------------------------------------------------------
*/

qx.Proto._addChildToChildrenQueue = function(vChild)
{
  if (!vChild._isInParentChildrenQueue && !vChild._isDisplayable) {
    this.warn("Ignoring invisible child: " + vChild);
  }

  if (!vChild._isInParentChildrenQueue && vChild._isDisplayable)
  {
    qx.ui.core.Widget.addToGlobalLayoutQueue(this);

    if (!this._childrenQueue) {
      this._childrenQueue = {};
    }

    this._childrenQueue[vChild.toHashCode()] = vChild;
  }
}

qx.Proto._removeChildFromChildrenQueue = function(vChild)
{
  if (this._childrenQueue && vChild._isInParentChildrenQueue)
  {
    delete this._childrenQueue[vChild.toHashCode()];

    if (qx.lang.Object.isEmpty(this._childrenQueue)) {
      qx.ui.core.Widget.removeFromGlobalLayoutQueue(this);
    }
  }
}

qx.Proto._flushChildrenQueue = function()
{
  if (!qx.lang.Object.isEmpty(this._childrenQueue))
  {
    this.getLayoutImpl().flushChildrenQueue(this._childrenQueue);
    delete this._childrenQueue;
  }
}







/*
---------------------------------------------------------------------------
  LAYOUT QUEUE
---------------------------------------------------------------------------
*/

qx.Proto._addChildrenToLayoutQueue = function(p)
{
  this.forEachChild(function() {
    this.addToLayoutChanges(p);
  });
}

qx.Proto._layoutChild = function(vChild)
{
  if (!vChild._isDisplayable)
  {
    this.warn("Want to render an invisible child: " + vChild + " -> omitting!");
    return;
  }

  // APPLY LAYOUT
  var vChanges = vChild._layoutChanges;

  // this.debug("Layouting " + vChild + ": " + qx.lang.Object.getKeysAsString(vChanges));

  try
  {
    if (vChanges.borderX) {
      this._applyBorderX(vChild, vChanges);
    }

    if (vChanges.borderY) {
      this._applyBorderY(vChild, vChanges);
    }
  }
  catch(ex)
  {
    this.error("Could not apply border to child " + vChild, ex);
  }

  try
  {
    if (vChanges.paddingLeft || vChanges.paddingRight) {
      vChild._applyPaddingX(this, vChanges);
    }

    if (vChanges.paddingTop || vChanges.paddingBottom) {
      vChild._applyPaddingY(this, vChanges);
    }
  }
  catch(ex)
  {
    this.error("Could not apply padding to child " + vChild, ex);
  }


  // WRAP TO LAYOUT ENGINE
  try
  {
    this.getLayoutImpl().layoutChild(vChild, vChanges);
  }
  catch(ex)
  {
    this.error("Could not layout child " + vChild + " through layout handler", ex);
  }


  // POST LAYOUT
  try
  {
    vChild._layoutPost(vChanges);
  }
  catch(ex)
  {
    this.error("Could not post layout child " + vChild, ex);
  }


  // DISPLAY DOM NODE
  try
  {
    // insert dom node (if initial flag enabled)
    if (vChanges.initial)
    {
      vChild._initialLayoutDone = true;
      qx.ui.core.Widget.addToGlobalDisplayQueue(vChild);
    }
  }
  catch(ex)
  {
    this.error("Could not handle display updates from layout flush for child " + vChild, ex);
  }


  // CLEANUP
  vChild._layoutChanges = {};

  delete vChild._isInParentLayoutQueue;
  delete this._childrenQueue[vChild.toHashCode()];
}

qx.Proto._layoutPost = qx.util.Return.returnTrue;

/*!
  Fix Operas Rendering Bugs
*/
if (qx.sys.Client.getInstance().isOpera())
{
  qx.Proto._layoutChildOrig = qx.Proto._layoutChild;

  qx.Proto._layoutChild = function(vChild)
  {
    if (!vChild._initialLayoutDone || !vChild._layoutChanges.borderX || !vChild._layoutChanges.borderY) {
      return this._layoutChildOrig(vChild);
    }

    var vStyle = vChild.getElement().style;

    var vOldDisplay = vStyle.display;
    vStyle.display = "none";
    var vRet = this._layoutChildOrig(vChild);
    vStyle.display = vOldDisplay;

    return vRet;
  }
}






/*
---------------------------------------------------------------------------
  DIMENSION CACHE
---------------------------------------------------------------------------
*/

qx.Proto._computePreferredInnerWidth = function() {
  return this.getLayoutImpl().computeChildrenNeededWidth();
}

qx.Proto._computePreferredInnerHeight = function() {
  return this.getLayoutImpl().computeChildrenNeededHeight();
}

qx.Proto._changeInnerWidth = function(vNew, vOld)
{
  var vLayout = this.getLayoutImpl();

  if (vLayout.invalidateChildrenFlexWidth) {
    vLayout.invalidateChildrenFlexWidth();
  }

  this.forEachVisibleChild(function()
  {
    if (vLayout.updateChildOnInnerWidthChange(this) && this._recomputeBoxWidth())
    {
      this._recomputeOuterWidth();
      this._recomputeInnerWidth();
    }
  });
}

qx.Proto._changeInnerHeight = function(vNew, vOld)
{
  var vLayout = this.getLayoutImpl();

  if (vLayout.invalidateChildrenFlexHeight) {
    vLayout.invalidateChildrenFlexHeight();
  }

  this.forEachVisibleChild(function()
  {
    if (vLayout.updateChildOnInnerHeightChange(this) && this._recomputeBoxHeight())
    {
      this._recomputeOuterHeight();
      this._recomputeInnerHeight();
    }
  });
}

qx.Proto.getInnerWidthForChild = function(vChild) {
  return this.getInnerWidth();
}

qx.Proto.getInnerHeightForChild = function(vChild) {
  return this.getInnerHeight();
}







/*
---------------------------------------------------------------------------
  WIDGET FROM POINT SUPPORT
---------------------------------------------------------------------------
*/

qx.Proto.getWidgetFromPointHelper = function(x, y)
{
  var ch = this.getChildren();

  for (var chl=ch.length, i=0; i<chl; i++) {
    if (qx.dom.ElementFromPoint.getElementAbsolutePointChecker(ch[i].getElement(), x, y)) {
      return ch[i].getWidgetFromPointHelper(x, y);
    }
  }

  return this;
}







/*
---------------------------------------------------------------------------
  CLONE
---------------------------------------------------------------------------
*/

qx.Proto._cloneRecursive = function(cloneInstance)
{
  var ch = this.getChildren();
  var chl = ch.length;
  var cloneChild;

  for (var i=0; i<chl; i++)
  {
    cloneChild = ch[i].clone(true);
    cloneInstance.add(cloneChild);
  }
}





/*
---------------------------------------------------------------------------
  REMAPPING
---------------------------------------------------------------------------
*/

qx.Proto._remappingChildTable = [ "add", "remove", "addAt", "addAtBegin", "addAtEnd", "removeAt", "addBefore", "addAfter", "removeAll" ];
qx.Proto._remapStart = "return this._remappingChildTarget.";
qx.Proto._remapStop = ".apply(this._remappingChildTarget, arguments)";

qx.Proto.remapChildrenHandlingTo = function(vTarget)
{
  var t = this._remappingChildTable;

  this._remappingChildTarget = vTarget;

  for (var i=0, l=t.length, s; i<l; i++) {
    s = t[i]; this[s] = new Function(qx.ui.core.Parent.prototype._remapStart + s + qx.ui.core.Parent.prototype._remapStop);
  }
}






/*
---------------------------------------------------------------------------
  DISPOSER
---------------------------------------------------------------------------
*/

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return;
  }

  if (this._layoutImpl)
  {
    this._layoutImpl.dispose();
    this._layoutImpl = null;
  }

  for (var i in this._childrenQueue) {
    delete this._childrenQueue[i];
  }

  this._childrenQueue = null;
  this._remappingChildTable = null;
  this._remappingChildTarget = null;

  if (this._children)
  {
    var chl = this._children.length;

    for (var i=chl-1; i>=0; i--)
    {
      this._children[i].dispose();
      this._children[i] = null;
    }

    this._children = null;
  }

  delete this._cachedVisibleChildren;

  // Remove Key Handler
  if (this.getFocusHandler())
  {
    this.removeEventListener("keydown", this._onfocuskeyevent);
    this.removeEventListener("keypress", this._onfocuskeyevent);

    this.forceFocusHandler(null);
  }

  return qx.ui.core.Widget.prototype.dispose.call(this);
}
