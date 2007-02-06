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

qx.OO.defineClass("qx.ui.layout.DockLayout", qx.ui.core.Parent,
function() {
  qx.ui.core.Parent.call(this);
});

/*!
  The layout mode (in which order the children should be layouted)
*/
qx.OO.addProperty({ name : "mode", type : "string", defaultValue : "vertical", possibleValues : [ "vertical", "horizontal", "ordered" ], addToQueueRuntime : true });

/*
  Overwrite from qx.ui.core.Widget, we do not support 'auto' and 'flex'
*/
qx.OO.changeProperty({ name : "width", addToQueue : true, unitDetection : "pixelPercent" });
qx.OO.changeProperty({ name : "minWidth", defaultValue : -Infinity, addToQueue : true, unitDetection : "pixelPercent" });
qx.OO.changeProperty({ name : "minWidth", defaultValue : -Infinity, addToQueue : true, unitDetection : "pixelPercent" });
qx.OO.changeProperty({ name : "height", addToQueue : true, unitDetection : "pixelPercent" });
qx.OO.changeProperty({ name : "minHeight", defaultValue : -Infinity, addToQueue : true, unitDetection : "pixelPercent" });
qx.OO.changeProperty({ name : "minHeight", defaultValue : -Infinity, addToQueue : true, unitDetection : "pixelPercent" });






/*
---------------------------------------------------------------------------
  INIT LAYOUT IMPL
---------------------------------------------------------------------------
*/

/*!
  This creates an new instance of the layout impl this widget uses
*/
qx.Proto._createLayoutImpl = function() {
  return new qx.renderer.layout.DockLayoutImpl(this);
}




/*
---------------------------------------------------------------------------
  ENHANCED CHILDREN FEATURES
---------------------------------------------------------------------------
*/

/*!
  Add multiple childrens and make them left aligned
*/
qx.Proto.addLeft = function() {
  this._addAlignedHorizontal("left", arguments);
}

/*!
  Add multiple childrens and make them right aligned
*/
qx.Proto.addRight = function() {
  this._addAlignedHorizontal("right", arguments);
}

/*!
  Add multiple childrens and make them top aligned
*/
qx.Proto.addTop = function() {
  this._addAlignedVertical("top", arguments);
}

/*!
  Add multiple childrens and make them bottom aligned
*/
qx.Proto.addBottom = function() {
  this._addAlignedVertical("bottom", arguments);
}

qx.Proto._addAlignedVertical = function(vAlign, vArgs)
{
  for (var i=0, l=vArgs.length; i<l; i++) {
    vArgs[i].setVerticalAlign(vAlign);
  }

  this.add.apply(this, vArgs);
}

qx.Proto._addAlignedHorizontal = function(vAlign, vArgs)
{
  for (var i=0, l=vArgs.length; i<l; i++) {
    vArgs[i].setHorizontalAlign(vAlign);
  }

  this.add.apply(this, vArgs);
}
