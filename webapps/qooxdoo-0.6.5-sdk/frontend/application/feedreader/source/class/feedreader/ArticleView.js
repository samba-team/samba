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
     * Fabian Jakobs (fjakobs)

************************************************************************ */

/* ************************************************************************

************************************************************************ */

qx.OO.defineClass("feedreader.ArticleView", qx.ui.basic.Terminator,
function(article) {
  qx.ui.basic.Terminator.call(this);
  this.setCssClassName("blogEntry");
  this.setArticle(article);
});

qx.OO.addProperty({ name: "article"});


qx.Proto._modifyArticle = function(propValue, propOldValue, propData) {
  if (this._isCreated) {
    this._applyElementData();
  }

  return true;
};


qx.Proto._applyElementData = function() {
  var element = this.getElement();
  element.innerHTML = this.getHtml();

  var links = element.getElementsByTagName("a");
  for (var i=0; i<links.length; i++) {
    links[i].target = "_blank";
  };
};


qx.Proto.getHtml = function() {
  var item = this.getArticle();
  if (!item) {
    return "";
  }

  var html = new qx.util.StringBuilder();

  html.add("<div id='_blogEntry'>");

  html.add("<h1 class='blog'>");
  html.add(item.title);
  html.add("</h1>");

  html.add("<div class='date'>");
  html.add(item.date);
  html.add("</div>");

  html.add("<div class='description'>");
  html.add(item.content);
  html.add("</div>");

  html.add("<a target='_blank' href='");
  html.add(item.link);
  html.add("'>");
  html.add(this.tr("read more ..."));
  html.add("</a>");

  html.add("</div>");

  return html;
}