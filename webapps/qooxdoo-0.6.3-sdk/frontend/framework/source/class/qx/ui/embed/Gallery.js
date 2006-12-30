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


************************************************************************ */

/**
 * @event beforeToolTipAppear {qx.event.type.Event}
 * @event loadComplete {qx.event.type.Event}
 */
qx.OO.defineClass("qx.ui.embed.Gallery", qx.ui.basic.Terminator,
function(vGalleryList)
{
  qx.ui.basic.Terminator.call(this);

  this._blank = qx.manager.object.AliasManager.getInstance().resolvePath("static/image/blank.gif");
  this._list = vGalleryList;
  this._listSize = vGalleryList.length;
  this._processedImages = 0;

  this.setOverflow("auto");

  this.setHtmlProperty("className", "qx_ui_embed_Gallery");

  this._manager = new qx.manager.selection.DomSelectionManager(this);

  this._manager.setMultiColumnSupport(true);

  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);
  this.addEventListener("mousemove", this._onmousemove);

  this.addEventListener("click", this._onclick);
  this.addEventListener("dblclick", this._ondblclick);

  this.addEventListener("keypress", this._onkeypress);
});





/*
---------------------------------------------------------------------------
  PROPERTIES
---------------------------------------------------------------------------
*/

qx.OO.addProperty({ name : "thumbMaxWidth", type : "number", defaultValue : 100 });
qx.OO.addProperty({ name : "thumbMaxHeight", type : "number", defaultValue : 100 });
qx.OO.addProperty({ name : "decorHeight", type : "number", defaultValue : 40 });
qx.OO.addProperty({ name : "showTitle", type : "boolean", defaultValue : true });
qx.OO.addProperty({ name : "showComment", type : "boolean", defaultValue : true });






/*
---------------------------------------------------------------------------
  ELEMENT HANDLING
---------------------------------------------------------------------------
*/

qx.Proto._applyElementData = function() {
  this.getElement().appendChild(this.createView());
}






/*
---------------------------------------------------------------------------
  UTILITIES
---------------------------------------------------------------------------
*/

qx.Proto.getManager = function() {
  return this._manager;
}

qx.Proto.getList = function() {
  return this._list;
}

qx.Proto.update = function(vGalleryList)
{
  this._manager.deselectAll();

  this._list = vGalleryList;

  var el = this.getElement();
  el.replaceChild(this.createView(), el.firstChild);
}

qx.Proto.removeAll = function()
{
  this._manager.deselectAll();
  this.getElement().innerHTML = "";
}

qx.Proto.updateImageById = function(vId, vSrc, vWidth, vHeight) {
  this.updateImageSrcById(vId, vSrc);
  this.updateImageDimensionsById(vId, vWidth, vHeight);
}

qx.Proto.updateImageDimensionsById = function(vId, vWidth, vHeight) {
  this.updateImageDimensionsByPosition(this.getPositionById(vId), vWidth, vHeight);
}

qx.Proto.updateImageDimensionsByPosition = function(vPos, vWidth, vHeight) {
  // TBD: compare dimensions with max. thumb size and scale proportionally if necessary
  if (vPos == -1) {
    throw new Error("No valid Position: " + vPos);
  }

  var cnode = this.getNodeByPosition(vPos).getElementsByTagName("img")[0];

  cnode.width = vWidth;
  cnode.height = vHeight;

  cnode.style.marginLeft = cnode.style.marginRight = Math.floor((this.getThumbMaxWidth()-vWidth)/2) + "px";
  cnode.style.marginTop = cnode.style.marginBottom = Math.floor((this.getThumbMaxHeight()-vHeight)/2) + "px";

  this._list[vPos].thumbWidth = vWidth;
  this._list[vPos].thumbHeight = vHeight;
}

qx.Proto.updateImageSrcById = function(vId, vSrc) {
  this.updateImageSrcByPosition(this.getPositionById(vId), vSrc);
}

qx.Proto.updateImageSrcByPosition = function(vPos, vSrc)
{
  if (vPos == -1) {
    throw new Error("No valid Position: " + vPos);
  }

  var vNode = this.getNodeByPosition(vPos);

  vNode.getElementsByTagName("img")[0].src = vSrc;
  this._list[vPos].src = vSrc;
}

qx.Proto.deleteById = function(vId) {
  this.deleteByPosition(this.getPositionById(vId));
}

qx.Proto.deleteByPosition = function(vPos)
{
  this._manager.deselectAll();

  if (vPos == -1) {
    throw new Error("No valid Position: " + vPos);
  }

  var vNode = this.getNodeByPosition(vPos);

  if (vNode) {
    vNode.parentNode.removeChild(vNode);
  }

  this._list.splice(vPos, 1);
}

qx.Proto.getPositionById = function(vId)
{
  for (var i=0, a=this._list, l=a.length; i<l; i++) {
    if (a[i].id == vId) {
      return i;
    }
  }

  return -1;
}

qx.Proto.getEntryById = function(vId) {
  return this.getEntryByPosition(this.getPositionById(vId));
}

qx.Proto.getNodeById = function(vId) {
  return this.getNodeByPosition(this.getPositionById(vId));
}

qx.Proto.getEntryByPosition = function(vPosition) {
  return vPosition == -1 ? null : this._list[vPosition];
}

qx.Proto.getNodeByPosition = function(vPosition) {
  return vPosition == -1 ? null : this._frame.childNodes[vPosition];
}

qx.Proto.getEntryByNode = function(vNode) {
  return this.getEntryById(vNode.id);
}

qx.Proto.addFromPartialList = function(vPartialList)
{
  this.concat(vPartialList);

  for (var i=0, a=vPartialList, l=a.length; i<l; i++) {
    this._frame.appendChild(this.createCell(a[i], i));
  }
}

qx.Proto.addFromUpdatedList = function(vNewList)
{
  for (var a=vNewList, l=a.length, i=this._list.length; i<l; i++) {
    this._frame.appendChild(this.createCell(a[i], i));
  }

  this._list = vNewList;
}




/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onmousedown = function(e)
{
  var vItem = this.getListItemTarget(e.getDomTarget());

  if (vItem) {
    this._manager.handleMouseDown(vItem, e);
  }
}

qx.Proto._onmouseup = function(e)
{
  var vItem = this.getListItemTarget(e.getDomTarget());

  if (vItem) {
    this._manager.handleMouseUp(vItem, e);
  }
}

qx.Proto._onmousemove = function(e)
{
  if (qx.OO.isAvailable("qx.manager.object.ToolTipManager")) {
    return;
  }

  var vItem = this.getListItemTarget(e.getDomTarget());

  if (vItem == this._lastItem) {
    return;
  }

  if (this._lastItem)
  {
    var vEventObject = new qx.event.type.MouseEvent("mouseout", e, false, this._lastItem);
    qx.manager.object.ToolTipManager.getInstance().handleMouseOut(vEventObject);
    vEventObject.dispose();
  }

  if (vItem)
  {
    if (this.hasEventListeners("beforeToolTipAppear")) {
      this.dispatchEvent(new qx.event.type.DataEvent("beforeToolTipAppear", vItem), true);
    }

    if (!this.getToolTip()) {
      return;
    }

    var vEventObject = new qx.event.type.MouseEvent("mouseout", e, false, vItem);
    qx.manager.object.ToolTipManager.getInstance().handleMouseOver(vEventObject);
    vEventObject.dispose();

    this.setToolTip(null);
  }

  this._lastItem = vItem;
}

qx.Proto._onclick = function(e)
{
  var vItem = this.getListItemTarget(e.getDomTarget());

  if (vItem) {
    this._manager.handleClick(vItem, e);
  }
}

qx.Proto._ondblclick = function(e)
{
  var vItem = this.getListItemTarget(e.getDomTarget());

  if (vItem) {
    this._manager.handleDblClick(vItem, e);
  }
}

qx.Proto._onkeypress = function(e) {
  this._manager.handleKeyPress(e);
}

qx.Proto.getListItemTarget = function(dt)
{
  while(dt.className.indexOf("galleryCell") == -1 && dt.tagName.toLowerCase() != "body") {
    dt = dt.parentNode;
  }

  if (dt.tagName.toLowerCase() == "body") {
    return null;
  }

  return dt;
}





/*
---------------------------------------------------------------------------
  SCROLL INTO VIEW
---------------------------------------------------------------------------
*/

qx.Proto.scrollItemIntoView = function(vItem)
{
  this.scrollItemIntoViewX(vItem);
  this.scrollItemIntoViewY(vItem);
}

qx.Proto.scrollItemIntoViewX = function(vItem) {
  qx.dom.ScrollIntoView.scrollX(vItem);
}

qx.Proto.scrollItemIntoViewY = function(vItem) {
  qx.dom.ScrollIntoView.scrollY(vItem);
}





/*
---------------------------------------------------------------------------
  MANAGER REQUIREMENTS
---------------------------------------------------------------------------
*/

qx.Proto.getItems = function() {
  return this._frame.childNodes;
}

qx.Proto.getFirstChild = function() {
  return this._frame.childNodes[0];
}

qx.Proto.getLastChild = function() {
  return this._frame.childNodes[this._frame.childNodes.length-1];
}







/*
---------------------------------------------------------------------------
  INTERNALS
---------------------------------------------------------------------------
*/

qx.Proto.createView = function()
{
  var s = (new Date).valueOf();

  if (!this._protoCell) {
    this.createProtoCell();
  }

  this._frame = document.createElement("div");
  this._frame.className = "galleryFrame clearfix";

  for (var i=0, a=this._list, l=a.length; i<l; i++) {
    this._frame.appendChild(this.createCell(a[i], i));
  }

  return this._frame;
}

qx.Proto.createCell = function(d, i)
{
  var cframe = this._protoCell.cloneNode(true);

  cframe.id = d.id;
  cframe.pos = i;

  if (this.getShowTitle())
  {
    cnode = cframe.childNodes[0];
    cnode.firstChild.nodeValue = d.title;
  }

  var cnode = cframe.childNodes[this.getShowTitle() ? 1 : 0];
  this.createImageCell(cnode, d);

  if (this.getShowComment())
  {
    cnode = cframe.childNodes[this.getShowTitle() ? 2 : 1];
    cnode.firstChild.nodeValue = d.comment;
  }

  return cframe;
}

qx.Proto._mshtml = qx.sys.Client.getInstance().isMshtml();

qx.Proto.createImageCell = function(inode, d)
{
  if (this.hasEventListeners("loadComplete"))
  {
    inode.onload = qx.ui.embed.Gallery.imageOnLoad;
    inode.onerror = qx.ui.embed.Gallery.imageOnError;
    inode.gallery = this;
  }

  if (this._mshtml) {
    inode.style.filter = "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='" + d.src + "',sizingMethod='scale')";
  } else {
    inode.src = d.src;
  }

  inode.width = d.thumbWidth + 2;
  inode.height = d.thumbHeight + 2;
  inode.style.marginLeft = inode.style.marginRight = Math.floor((this.getThumbMaxWidth()-d.thumbWidth)/2) + "px";
  inode.style.marginTop = inode.style.marginBottom = Math.floor((this.getThumbMaxHeight()-d.thumbHeight)/2) + "px";
}

qx.Proto.imageOnComplete = function()
{
  this._processedImages++;

  if(this._processedImages == this._listSize) {
    this.dispatchEvent(new qx.event.type.Event("loadComplete"), true);
  }
}

qx.ui.embed.Gallery.imageOnLoad = function()
{
  this.gallery.imageOnComplete();
  this.gallery = null;
  this.onload = null;
  this.onerror = null;
}

qx.ui.embed.Gallery.imageOnError = function()
{
  this.gallery.imageOnComplete();
  this.gallery = null;
  this.onload = null;
  this.onerror = null;
}

qx.Proto.createProtoCell = function()
{
  var frame = this._protoCell = document.createElement("div");
  frame.className = "galleryCell";
  frame.unselectable = "on";
  frame.style.width = (this.getThumbMaxWidth() + 2) + "px";
  frame.style.height = (this.getThumbMaxHeight() + this.getDecorHeight() + 2) + "px";

  if (this.getShowTitle())
  {
    var title = document.createElement("div");
    title.className = "galleryTitle";
    title.unselectable = "on";
    var ttext = document.createTextNode("-");
    title.appendChild(ttext);

    frame.appendChild(title);
  }

  var image = new Image();
  image.src = this._blank;
  frame.appendChild(image);

  if (this.getShowComment())
  {
    var comment = document.createElement("div");
    comment.className = "galleryComment";
    comment.unselectable = "on";
    var ctext = document.createTextNode("-");
    comment.appendChild(ctext);

    frame.appendChild(comment);
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
    return true;
  }

  this._list = null;
  this._protoCell = null;
  this._frame = null;

  if (this._manager)
  {
    this._manager.dispose();
    this._manager = null;
  }

  this.removeEventListener("mousedown", this._onmousedown);
  this.removeEventListener("mouseup", this._onmouseup);
  this.removeEventListener("mousemove", this._onmousemove);

  this.removeEventListener("click", this._onclick);
  this.removeEventListener("dblclick", this._ondblclick);

  this.removeEventListener("keypress", this._onkeypress);

  return qx.ui.basic.Terminator.prototype.dispose.call(this);
}
