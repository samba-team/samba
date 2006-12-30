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

#module(core)

************************************************************************ */

qx.OO.defineClass("qx.component.init.BasicInitComponent", qx.component.init.AbstractInitComponent,
function() {
  qx.component.init.AbstractInitComponent.call(this);
});





/*
---------------------------------------------------------------------------
  EVENT HANDLER
---------------------------------------------------------------------------
*/

qx.Proto._onload = function(e)
{
  this.initialize(e);
  this.main(e);
  this.finalize(e);
}

qx.Proto._onbeforeunload = function(e) {
  this.close(e);
}

qx.Proto._onunload = function(e) {
  this.terminate(e);
}
