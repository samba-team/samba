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

#module(ui_menu)

************************************************************************ */

qx.OO.defineClass("qx.renderer.layout.MenuLayoutImpl", qx.renderer.layout.VerticalBoxLayoutImpl,
function(vWidget)
{
  qx.renderer.layout.VerticalBoxLayoutImpl.call(this, vWidget);

  // We don't need flex support, should make things a bit faster,
  // as this omits some additional loops in qx.renderer.layout.HorizontalBoxLayoutImpl.
  this.setEnableFlexSupport(false);
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


  Inherits from qx.renderer.layout.VerticalBoxLayoutImpl:
  [01] COMPUTE BOX DIMENSIONS FOR AN INDIVIDUAL CHILD
  [02] COMPUTE NEEDED DIMENSIONS FOR AN INDIVIDUAL CHILD
  [03] COMPUTE NEEDED DIMENSIONS FOR ALL CHILDREN
  [04] UPDATE LAYOUT WHEN A CHILD CHANGES ITS OUTER DIMENSIONS
  [05] UPDATE CHILD ON INNER DIMENSION CHANGES OF LAYOUT
  [06] UPDATE LAYOUT ON JOB QUEUE FLUSH
  [08] CHILDREN ADD/REMOVE/MOVE HANDLING
  [09] FLUSH LAYOUT QUEUES OF CHILDREN
  [10] LAYOUT CHILD
  [11] DISPOSER
*/




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
  var vWidget = this.getWidget();
  var ch, chc;

  if (vQueue.preferredInnerWidth)
  {
    var ch = vWidget.getChildren(), chl = ch.length, chc;
    var sch, schl;

    for (var i=0; i<chl; i++)
    {
      chc = ch[i];
      sch = chc.getChildren();
      schl = sch.length;

      for (var j=0; j<schl; j++) {
        sch[j].addToLayoutChanges("locationX");
      }
    }
  }

  // Call superclass implementation
  return qx.renderer.layout.VerticalBoxLayoutImpl.prototype.updateChildrenOnJobQueueFlush.call(this, vQueue);
}
