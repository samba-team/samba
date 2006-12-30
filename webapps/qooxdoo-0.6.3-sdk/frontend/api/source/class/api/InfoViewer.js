/*
#module(api)
*/

/**
 * Shows the class details.
 */
qx.OO.defineClass("api.InfoViewer", qx.ui.embed.HtmlEmbed,
function() {
  qx.ui.embed.HtmlEmbed.call(this);

  this.setOverflow("auto");
  this.setPadding(20);
  this.setEdge(0);
  this.setHtmlProperty("id", "InfoViewer");
  this.setVisibility(false);

  api.InfoViewer.instance = this;
});

qx.Proto.showInfo = function(classNode)
{
  var vHtml = "";

  // Title
  vHtml += '<h1>';
  vHtml += '<div class="pkgtitle">package</div>';
  vHtml += classNode.attributes.fullName;
  vHtml += '</h1>';

  // TODO: Overview of classes in this package

  // Apply HTML
  this.setHtml(vHtml);
}
