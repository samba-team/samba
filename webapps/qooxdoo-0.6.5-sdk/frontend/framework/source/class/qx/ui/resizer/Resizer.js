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
     * David Perez (david-perez)

************************************************************************ */

/* ************************************************************************

#module(ui_resizer)

************************************************************************ */

/**
 * This class acts as a wrapper for other child, and allows it to be resized (not moved), normally in
 * the right and/or bottom directions.  Child can be e.g. a qx.ui.form.TextArea,
 * qx.ui.table.Table or qx.ui.form.List.  It is an alternative to splitters.
 */
qx.OO.defineClass('qx.ui.resizer.Resizer', qx.ui.layout.CanvasLayout,
function(child)
{
  qx.ui.layout.CanvasLayout.call(this);

  this._frame = new qx.ui.basic.Terminator;
  this._frame.setAppearance("resizer-frame");

  this._registerResizeEvents();

  this.setAppearance('resizer');
  this.setResizeableWest(false);
  this.setResizeableNorth(false);

  this.setMinWidth("auto");
  this.setMinHeight("auto");
  this.auto();

  if (child)
  {
    // Remove child border, as the resizer has already its own border.
    child.setBorder(new qx.renderer.border.Border(0));
    this.add(this._child = child);
  }
});





/*!
  If the window is resizeable in the left direction.
*/
qx.OO.addProperty({ name : "resizeableWest", type : "boolean", defaultValue : true });
/*!
  If the window is resizeable in the top direction.
*/
qx.OO.addProperty({ name : "resizeableNorth", type : "boolean", defaultValue : true });
/*!
  If the window is resizeable in the right direction.
*/
qx.OO.addProperty({ name : "resizeableEast", type : "boolean", defaultValue : true });
/*!
  If the window is resizeable in the bottom direction.
*/
qx.OO.addProperty({ name : "resizeableSouth", type : "boolean", defaultValue : true });

/*!
  If the window is resizeable
*/
qx.OO.addPropertyGroup({ name : "resizeable", members : [ "west", "north", "east", "south" ], mode : "shorthand" });

/*!
  The resize method to use
*/
qx.OO.addProperty({ name : "resizeMethod", type : "string", defaultValue : "frame", possibleValues : [ "opaque", "lazyopaque", "frame", "translucent" ] });

/*!
  The resize method to use
*/
qx.OO.addProperty({ name : "resizeMethod", type : "string", defaultValue : "frame", possibleValues : [ "opaque", "lazyopaque", "frame", "translucent" ] });






/**
 * Adjust so that it returns a boolean instead of an array.
 * @return {Boolean}
 */
qx.Proto.isResizeable = qx.Proto.getResizeable = function() {
  return this.getResizeableWest() || this.getResizeableEast() || this.getResizeableNorth() || this.getResizeableSouth();
}

qx.Proto._registerResizeEvents = function() {
  this.addEventListener("mousedown", this._onmousedown);
  this.addEventListener("mouseup", this._onmouseup);
  this.addEventListener("mousemove", this._onmousemove);
}

qx.Proto._onmousedown = function(e)
{
  if (this._resizeNorth || this._resizeSouth || this._resizeWest || this._resizeEast)
  {
    // enable capturing
    this.setCapture(true);

    // activate global cursor
    this.getTopLevelWidget().setGlobalCursor(this.getCursor());

    // caching element
    var el = this.getElement();

    // measuring and caching of values for resize session
    var pa = this.getTopLevelWidget();
    var pl = pa.getElement();

    var l = qx.html.Location.getPageAreaLeft(pl);
    var t = qx.html.Location.getPageAreaTop(pl);
    var r = qx.html.Location.getPageAreaRight(pl);
    var b = qx.html.Location.getPageAreaBottom(pl);

    // handle frame and translucently
    switch(this.getResizeMethod())
    {
      case "translucent":
        this.setOpacity(0.5);
        break;

      case "frame":
        var f = this._frame;

        if (f.getParent() != pa)
        {
          f.setParent(pa);
          qx.ui.core.Widget.flushGlobalQueues();
        }

        f._applyRuntimeLeft(qx.html.Location.getPageBoxLeft(el) - l);
        f._applyRuntimeTop(qx.html.Location.getPageBoxTop(el) - t);

        f._applyRuntimeWidth(qx.html.Dimension.getBoxWidth(el));
        f._applyRuntimeHeight(qx.html.Dimension.getBoxHeight(el));

        f.setZIndex(this.getZIndex() + 1);

        break;
    }

    // create resize session
    var s = this._resizeSession = {};
    var minRef = this._child;

    if (this._resizeWest)
    {
      s.boxWidth = qx.html.Dimension.getBoxWidth(el);
      s.boxRight = qx.html.Location.getPageBoxRight(el);
    }

    if (this._resizeWest || this._resizeEast)
    {
      s.boxLeft = qx.html.Location.getPageBoxLeft(el);

      s.parentAreaOffsetLeft = l;
      s.parentAreaOffsetRight = r;

      s.minWidth = minRef.getMinWidthValue();
      s.maxWidth = minRef.getMaxWidthValue();
    }

    if (this._resizeNorth)
    {
      s.boxHeight = qx.html.Dimension.getBoxHeight(el);
      s.boxBottom = qx.html.Location.getPageBoxBottom(el);
    }

    if (this._resizeNorth || this._resizeSouth)
    {
      s.boxTop = qx.html.Location.getPageBoxTop(el);

      s.parentAreaOffsetTop = t;
      s.parentAreaOffsetBottom = b;

      s.minHeight = minRef.getMinHeightValue();
      s.maxHeight = minRef.getMaxHeightValue();
    }
  }
  else
  {
    // cleanup resize session
    delete this._resizeSession;
  }

  // stop event
  e.stopPropagation();
}

qx.Proto._onmouseup = function(e)
{
  var s = this._resizeSession;

  if (s)
  {
    // disable capturing
    this.setCapture(false);

    // deactivate global cursor
    this.getTopLevelWidget().setGlobalCursor(null);

    // sync sizes to frame
    switch(this.getResizeMethod())
    {
      case "frame":
        var o = this._frame;
        if (!(o && o.getParent())) {
          break;
        }
        // no break here

      case "lazyopaque":
        if (s.lastLeft != null) {
          this.setLeft(s.lastLeft);
        }

        if (s.lastTop != null) {
          this.setTop(s.lastTop);
        }

        if (s.lastWidth != null) {
          var child = this.getChildren()[0];
          if (child) {
            child.setWidth(s.lastWidth);
          }
        }

        if (s.lastHeight != null) {
          var child = this.getChildren()[0];
          if (child) {
            child.setHeight(s.lastHeight);
          }
        }

        if (this.getResizeMethod() == "frame") {
          this._frame.setParent(null);
        }
        break;

      case "translucent":
        this.setOpacity(null);
        break;
    }

    // cleanup session
    delete this._resizeNorth;
    delete this._resizeEast;
    delete this._resizeSouth;
    delete this._resizeWest;

    delete this._resizeSession;
  }

  // stop event
  e.stopPropagation();
}

qx.Proto._near = function(p, e) {
  return e > (p - 5) && e < (p + 5);
}

qx.Proto._onmousemove = function(e)
{
  var s = this._resizeSession;

  if (s)
  {
    if (this._resizeWest)
    {
      s.lastWidth = qx.lang.Number.limit(s.boxWidth + s.boxLeft - Math.max(e.getPageX(), s.parentAreaOffsetLeft), s.minWidth, s.maxWidth);
      s.lastLeft = s.boxRight - s.lastWidth - s.parentAreaOffsetLeft;
    }
    else if (this._resizeEast)
    {
      s.lastWidth = qx.lang.Number.limit(Math.min(e.getPageX(), s.parentAreaOffsetRight) - s.boxLeft, s.minWidth, s.maxWidth);
    }

    if (this._resizeNorth)
    {
      s.lastHeight = qx.lang.Number.limit(s.boxHeight + s.boxTop - Math.max(e.getPageY(), s.parentAreaOffsetTop), s.minHeight, s.maxHeight);
      s.lastTop = s.boxBottom - s.lastHeight - s.parentAreaOffsetTop;
    }
    else if (this._resizeSouth)
    {
      s.lastHeight = qx.lang.Number.limit(Math.min(e.getPageY(), s.parentAreaOffsetBottom) - s.boxTop, s.minHeight, s.maxHeight);
    }

    switch(this.getResizeMethod())
    {
      case "opaque":
      case "translucent":
        if (this._resizeWest || this._resizeEast)
        {
          this.setWidth(s.lastWidth);

          if (this._resizeWest) {
            this.setLeft(s.lastLeft);
          }
        }

        if (this._resizeNorth || this._resizeSouth)
        {
          this.setHeight(s.lastHeight);

          if (this._resizeNorth) {
            this.setTop(s.lastTop);
          }
        }

        break;

      default:
        var o = this.getResizeMethod() == "frame" ? this._frame : this;

        if (this._resizeWest || this._resizeEast)
        {
          o._applyRuntimeWidth(s.lastWidth);

          if (this._resizeWest) {
            o._applyRuntimeLeft(s.lastLeft);
          }
        }

        if (this._resizeNorth || this._resizeSouth)
        {
          o._applyRuntimeHeight(s.lastHeight);

          if (this._resizeNorth) {
            o._applyRuntimeTop(s.lastTop);
          }
        }
    }
  }
  else
  {
    var resizeMode = "";
    var el = this.getElement();

    this._resizeNorth = this._resizeSouth = this._resizeWest = this._resizeEast = false;

    if (this._near(qx.html.Location.getPageBoxTop(el), e.getPageY()))
    {
      if (this.getResizeableNorth()) {
        resizeMode = "n";
        this._resizeNorth = true;
      }
    }
    else if (this._near(qx.html.Location.getPageBoxBottom(el), e.getPageY()))
    {
      if (this.getResizeableSouth()) {
        resizeMode = "s";
        this._resizeSouth = true;
      }
    }

    if (this._near(qx.html.Location.getPageBoxLeft(el), e.getPageX()))
    {
      if (this.getResizeableWest()) {
        resizeMode += "w";
        this._resizeWest = true;
      }
    }
    else if (this._near(qx.html.Location.getPageBoxRight(el), e.getPageX()))
    {
      if (this.getResizeableEast()) {
        resizeMode += "e";
        this._resizeEast = true;
      }
    }

    if (this._resizeNorth || this._resizeSouth || this._resizeWest || this._resizeEast)
    {
      this.setCursor(resizeMode + "-resize");
    }
    else
    {
      this.setCursor(null);
    }
  }

  // stop event
  e.stopPropagation();
}

qx.Proto.dispose = function()
{
  if (this.getDisposed()) {
    return true;
  }

  if (this._frame)
  {
    this._frame.dispose();
    this._frame = null;
  }

  return qx.ui.layout.CanvasLayout.prototype.dispose.call(this);
}
