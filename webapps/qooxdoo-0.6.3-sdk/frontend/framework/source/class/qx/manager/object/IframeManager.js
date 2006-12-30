/* ************************************************************************

   qooxdoo - the new era of web development

   http://qooxdoo.org

   Copyright:
     2004-2006 by 1&1 Internet AG, Germany, http://www.1and1.org

   License:
     LGPL 2.1: http://www.gnu.org/licenses/lgpl.html

   Authors:
     * Til Schneider (til132)

************************************************************************ */

/**
 * This singleton manages multiple instances of qx.ui.embed.Iframe.
 * <p>
 * The problem: When dragging over an iframe then all mouse events will be
 * passed to the document of the iframe, not the main document.
 * <p>
 * The solution: In order to be able to track mouse events over iframes, this
 * manager will block all iframes during a drag with a glasspane.
 */
qx.OO.defineClass("qx.manager.object.IframeManager", qx.manager.object.ObjectManager,
function(){
  qx.manager.object.ObjectManager.call(this);
});





/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

qx.Proto.handleMouseDown = function(evt) {
  var iframeMap = this.getAll();

  for (var key in iframeMap) {
    var iframe = iframeMap[key];
    iframe.block();
  }
}

qx.Proto.handleMouseUp = function(evt) {
  var iframeMap = this.getAll();

  for (var key in iframeMap) {
    var iframe = iframeMap[key];
    iframe.release();
  }
}







/*
---------------------------------------------------------------------------
  DEFER SINGLETON INSTANCE
---------------------------------------------------------------------------
*/

/**
 * Singleton Instance Getter
 */
qx.Class.getInstance = qx.util.Return.returnInstance;
