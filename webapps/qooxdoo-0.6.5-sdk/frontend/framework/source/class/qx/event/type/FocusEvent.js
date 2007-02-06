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

************************************************************************ */

/*!
  This event handles all focus events.

  The four supported types are:
  1+2: focus and blur also propagate the target object
  3+4: focusout and focusin are bubbling to the parent objects
*/
qx.OO.defineClass("qx.event.type.FocusEvent", qx.event.type.Event,
function(vType, vTarget)
{
  qx.event.type.Event.call(this, vType);

  this.setTarget(vTarget);

  switch(vType)
  {
    case "focusin":
    case "focusout":
      this.setBubbles(true);
      this.setPropagationStopped(false);
  }
});
