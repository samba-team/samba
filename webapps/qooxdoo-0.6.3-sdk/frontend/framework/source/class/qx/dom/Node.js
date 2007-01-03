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

qx.OO.defineClass("qx.dom.Node",
{
  ELEMENT : 1,
  ATTRIBUTE : 2,
  TEXT : 3,
  CDATA_SECTION : 4,
  ENTITY_REFERENCE : 5,
  ENTITY : 6,
  PROCESSING_INSTRUCTION : 7,
  COMMENT : 8,
  DOCUMENT : 9,
  DOCUMENT_TYPE : 10,
  DOCUMENT_FRAGMENT : 11,
  NOTATION : 12
});
