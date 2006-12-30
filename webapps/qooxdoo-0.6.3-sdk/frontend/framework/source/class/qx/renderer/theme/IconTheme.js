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
#after(qx.manager.object.ImageManager)

************************************************************************ */

qx.OO.defineClass("qx.renderer.theme.IconTheme", qx.core.Object,
function(vTitle)
{
  qx.core.Object.call(this);

  this.setTitle(vTitle);
});

qx.OO.addProperty({ name : "title", type : "string", allowNull : false, defaultValue : "" });
