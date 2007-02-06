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

#resource(feeds:feeds)
#resource(css:css)
#resource(proxy:proxy)
#resource(images:images)
#embed(feedreader.proxy/*)
#embed(feedreader.feeds/*)
#embed(feedreader.css/*)
#embed(feedreader.images/*)
#embed(qx.icontheme/16/actions/dialog-ok.png)
#embed(qx.icontheme/16/actions/dialog-cancel.png)
#embed(qx.icontheme/16/actions/help-about.png)
#embed(qx.icontheme/16/actions/view-refresh.png)

************************************************************************ */

/**
 * qooxdoo news reader Application class.
 */
qx.OO.defineClass("feedreader.Application", qx.component.AbstractApplication,
function () {
  qx.component.AbstractApplication.call(this);

  qx.manager.object.ImageManager.getInstance().setIconTheme(qx.theme.icon.VistaInspirate.getInstance());
  //this.fetchFeedDesc();
  this.setFeeds([]);
});

qx.OO.addProperty({name: "feeds"});
qx.OO.addProperty({name: "selectedFeed"});

qx.Settings.setDefault("resourceUri", "./resource");



/*
---------------------------------------------------------------------------
  METHODS
---------------------------------------------------------------------------
*/

if (qx.core.Client.getInstance().getRunsLocally())
{
  qx.Class._feedDesc = [
    {
      url: "feedreader/feeds/qooxdoo-news.xml",
      name: "qooxdoo-blog"
    },
    {
      url: "feedreader/feeds/qooxdoo-blog.xml",
      name: "qooxdoo-news"
    },
    {
      url: "feedreader/feeds/ajaxian.xml",
      name: "ajaxian"
    },
    {
      url: "feedreader/feeds/safari.xml",
      name: "Surfin' Safari"
    }
  ];
}
else
{
  qx.Class._feedDesc = [
    {
      url: "feedreader/proxy/proxy.php?proxy=" + encodeURIComponent("http://feeds.feedburner.com/qooxdoo/blog/content"),
      name: "qooxdoo-blog"
    },
    {
      url: "feedreader/proxy/proxy.php?proxy=" + encodeURIComponent("http://feeds.feedburner.com/qooxdoo/news/content"),
      name: "qooxdoo-news"
    },
    {
      url: "feedreader/proxy/proxy.php?proxy=" + encodeURIComponent("http://feeds.feedburner.com/ajaxian"),
      name: "ajaxian"
    },
    {
      url: "feedreader/proxy/proxy.php?proxy=" + encodeURIComponent("http://webkit.org/blog/?feed=rss2"),
      name: "Surfin' Safari"
    }
  ];
}

qx.Proto.initialize = function(e)
{
  // Define alias for custom resource path
  qx.manager.object.AliasManager.getInstance().add("feedreader", qx.Settings.getValueOfClass("feedreader.Application", "resourceUri"));

  // Include CSS file
  qx.html.StyleSheet.includeFile(qx.manager.object.AliasManager.getInstance().resolvePath("feedreader/css/reader.css"));
};

qx.Proto.main = function(e)
{
  // create main layout
  var dockLayout = new qx.ui.layout.DockLayout();
  dockLayout.set({
    height: "100%",
    width: "100%"
  });

  // create header
  var header = new qx.ui.embed.HtmlEmbed("<h1><span>qooxdoo</span> reader</h1>");
  header.setCssClassName("header");
  header.setHeight(50);
  dockLayout.addTop(header);

  // define commands
  var reload_cmd = new qx.client.Command("Control+R");
  reload_cmd.addEventListener("execute", function(e) {
    this.fetchFeeds();
    this.debug(this.tr("reloading ...").toString());
  }, this);

  var about_cmd = new qx.client.Command("F1");
  about_cmd.addEventListener("execute", function(e) {
    alert(this.tr("qooxdoo feed reader."));
  }, this);

  // create toolbar
  var toolBar = new qx.ui.toolbar.ToolBar();
  toolBar.add(new qx.ui.toolbar.Button(this.trn("Add feed", "Add feeds", 2), "icon/16/actions/dialog-ok.png"));
  toolBar.add(new qx.ui.toolbar.Button(this.tr("Remove feed"), "icon/16/actions/dialog-cancel.png"));
  toolBar.add(new qx.ui.toolbar.Separator());

  var reload_btn = new qx.ui.toolbar.Button(this.tr("Reload"), "icon/16/actions/view-refresh.png");
  reload_btn.setCommand(reload_cmd);
  reload_btn.setToolTip(new qx.ui.popup.ToolTip(this.tr("(%1) Reload the feeds.", reload_cmd.toString())));
  toolBar.add(reload_btn);

  toolBar.add(new qx.ui.basic.HorizontalSpacer());

  // poulate languages menu and add it to the toolbar
  var locales = {
    en: this.tr("English"),
    de: this.tr("German"),
    en: this.tr("English"),
    tr: this.tr("Turkish"),
    it: this.tr("Italian"),
    es: this.tr("Spanish"),
    sv: this.tr("Swedish"),
    ru: this.tr("Russian")
  }
  var availableLocales = qx.locale.Manager.getInstance().getAvailableLocales();
  var locale = qx.locale.Manager.getInstance().getLocale();
  var lang_menu = new qx.ui.menu.Menu();
  var radioManager = new qx.manager.selection.RadioManager("lang");
  for (var lang in locales) {
    if (availableLocales.indexOf(lang) == -1) {
      continue;
    }
    var menuButton = new qx.ui.menu.RadioButton(locales[lang], null, locale == lang);
    menuButton.setUserData("locale", lang);
    lang_menu.add(menuButton);
    radioManager.add(menuButton);
  }
  radioManager.addEventListener("changeSelected", function(e) {
    var lang = e.getData().getUserData("locale");
    this.debug("lang:" + lang);
  qx.locale.Manager.getInstance().setLocale(lang);
  });
  lang_menu.addToDocument();
  toolBar.add(new qx.ui.toolbar.MenuButton("", lang_menu, "feedreader/images/locale.png"));

  var about_btn = new qx.ui.toolbar.Button(this.tr("Help"), "icon/16/actions/help-about.png");
  about_btn.setCommand(about_cmd);
  about_btn.setToolTip(new qx.ui.popup.ToolTip("(" + about_cmd.toString() + ")"));
  toolBar.add(about_btn);

  dockLayout.addTop(toolBar);

  // add tree
  var tree = new qx.ui.tree.Tree(this.tr("News feeds"));
  tree.set({height:"100%", width:"100%"});
  tree.setOverflow("auto");
  tree.setBorder(qx.renderer.border.BorderPresets.getInstance().inset);
  tree.setBackgroundColor("#EEEEEE");

  var feedDesc = feedreader.Application._feedDesc;
  for (var i=0; i<feedDesc.length; i++) {
    var folder = new qx.ui.tree.TreeFolder(feedDesc[i].name);
    tree.getManager().addEventListener("changeSelection", function(e) {
      if (e.getData()[0] .getParentFolder()) {
        this.displayFeed(e.getData()[0].getLabel());
      }
    }, this);
    tree.add(folder);
  }

  // create table model
  this._tableModel = new qx.ui.table.SimpleTableModel();
  this._tableModel.setColumnIds(["title", "author", "date"]);
  this._tableModel.setColumnNamesById({
    title: this.tr("Subject"),
    author: this.tr("Sender"),
    date: this.tr("Date")
  });

  // add table
  var table = new qx.ui.table.Table(this._tableModel);
  table.setBorder(qx.renderer.border.BorderPresets.getInstance().inset);
  table.set({height:"100%", width:"100%"});
  table.setStatusBarVisible(false);
  table.getDataRowRenderer().setHighlightFocusRow(false);
  table.getTableColumnModel().setColumnWidth(0, 350);
  table.getTableColumnModel().setColumnWidth(1, 200);
  table.getTableColumnModel().setColumnWidth(2, 200);
  table.getSelectionModel().addEventListener("changeSelection", function(e) {
    var selectedEntry = table.getSelectionModel().getAnchorSelectionIndex();
    var item = this.getFeeds()[this.getSelectedFeed()].items[selectedEntry];
    this.displayArticle(item);
  }, this);

  // hide row focus
  var theme = qx.manager.object.AppearanceManager.getInstance().getAppearanceTheme();
  theme.registerAppearance("table-focus-indicator", {
    state : function(vTheme, vStates) {
      return {
        border: null
      }
    }
  });
  this._table = table;

  // add blog entry
  this._blogEntry = new feedreader.ArticleView();
  this._blogEntry.set({height:"100%", width:"100%"});
  this._blogEntry.setBorder(qx.renderer.border.BorderPresets.getInstance().inset);

  // create splitpane for the right hand content area
  var contentSplitPane = new qx.ui.splitpane.VerticalSplitPane("1*", "2*");
  contentSplitPane.set({height:"100%", width:"100%"});
  contentSplitPane.setLiveResize(true);
  contentSplitPane.addTop(table);
  contentSplitPane.addBottom(this._blogEntry);

  // create vertival splitter
  var mainSplitPane = new qx.ui.splitpane.HorizontalSplitPane(200, "1*");
  mainSplitPane.setLiveResize(true);
  mainSplitPane.addLeft(tree);
  mainSplitPane.addRight(contentSplitPane);

  dockLayout.add(mainSplitPane);

  dockLayout.addToDocument();

  // load and display feed data
  this.setSelectedFeed(feedDesc[0].name);
  this.fetchFeeds();
};


qx.Proto.fetchFeedDesc = function() {
  var req = new qx.io.remote.Request(qx.manager.object.AliasManager.getInstance().resolvePath("feedreader/feeds/febo-feeds.opml.xml"), "GET", qx.util.Mime.XML);
  feedreader.Application._feedDesc = [];
    req.addEventListener("completed", function(e) {
    var xml = e.getData().getContent();
    var eItems = xml.getElementsByTagName("outline");
    for(var i=0; i<eItems.length; i++) {
      var eDesc = eItems[i];
      feedreader.Application._feedDesc.push({
        name: eDesc.getAttribute("title"),
        url: qx.manager.object.AliasManager.getInstance().resolvePath("feedreader/proxy/proxy.php") + "?proxy=" + encodeURIComponent(eDesc.getAttribute("xmlUrl"))
      });
    }
  }, this);
  req.setAsynchronous(false);
    req.send();
};


qx.Proto.fetchFeeds = function() {
  qx.io.remote.RequestQueue.getInstance().setMaxConcurrentRequests(2);
  var feedDesc = feedreader.Application._feedDesc;
  var that = this;
  var getCallback = function(feedName) {
    return function(e) {
      that.debug("loading " + feedName + " complete!");
      that.parseXmlFeed(feedName, e.getData().getContent());
    }
  }
  for (var i=0; i<feedDesc.length; i++) {
    var req = new qx.io.remote.Request(qx.manager.object.AliasManager.getInstance().resolvePath(feedDesc[i].url), "GET", qx.util.Mime.XML);
    req.addEventListener("completed", getCallback(feedDesc[i].name));
    req.send();
  }
};


qx.Proto.parseXmlFeed = function(feedName, xml) {
  var items = [];
  if (xml.documentElement.tagName == "rss") {
    items = this.parseRSSFeed(xml);
  } else if  (xml.documentElement.tagName == "feed") {
  items = this.parseAtomFeed(xml);
  }
  this.getFeeds()[feedName] = {
    selected: 0,
    items: items
  };
  if (feedName == this.getSelectedFeed()) {
    this.displayFeed(feedName);
  }
};


qx.Proto.parseAtomFeed = function(xml) {
  var eItems = xml.getElementsByTagName("entry");
  var empty = xml.createElement("empty");
  var items = [];
  for (var i=0; i<eItems.length; i++) {
    var eItem = eItems[i];
    var item = {}
    item.title = qx.dom.Element.getTextContent(eItem.getElementsByTagName("title")[0]);
    if (eItem.getElementsByTagName("author").length > 0) {
      item.author = qx.dom.Element.getTextContent(eItem.getElementsByTagName("author")[0].getElementsByTagName("name")[0]);
    } else {
    item.author = ""
    }
    item.date = qx.dom.Element.getTextContent(
    eItem.getElementsByTagName("created")[0] ||
    eItem.getElementsByTagName("published")[0] ||
    eItem.getElementsByTagName("updated")[0] ||
    empty
  );
    item.content = qx.dom.Element.getTextContent(eItem.getElementsByTagName("content")[0] || empty);
    item.link = eItem.getElementsByTagName("link")[0].getAttribute("href");
    items.push(item);
  }
  return items;
}


qx.Proto.parseRSSFeed = function(xml) {
  var eItems = xml.getElementsByTagName("item");
  var empty = xml.createElement("empty");
  var items = [];
  for (var i=0; i<eItems.length; i++) {
    var eItem = eItems[i];
    var item = {}
    item.title = qx.dom.Element.getTextContent(eItem.getElementsByTagName("title")[0]);
    item.author = qx.dom.Element.getTextContent(qx.xml.Element.getElementsByTagNameNS(eItem, qx.xml.Namespace.DC, "creator")[0] || empty);
    item.date = qx.dom.Element.getTextContent(eItem.getElementsByTagName("pubDate")[0]);
    item.content = qx.dom.Element.getTextContent(qx.xml.Element.getElementsByTagNameNS(eItem, qx.xml.Namespace.RSS1, "encoded")[0] || empty);
    item.link = qx.dom.Element.getTextContent(eItem.getElementsByTagName("link")[0]);
    items.push(item);
  }
  return items;
};


qx.Proto.displayFeed = function(feedName) {
  if (this.getSelectedFeed() != feedName) {
    this.getFeeds()[this.getSelectedFeed()].selected = this._table.getSelectionModel().getAnchorSelectionIndex();
  }

  this.setSelectedFeed(feedName);

  if (this.getFeeds()[feedName]) {
    var items = this.getFeeds()[feedName].items;
    var selection = this.getFeeds()[feedName].selected;

    this._tableModel.setDataAsMapArray(items);
    this._table.getSelectionModel().setSelectionInterval(selection, selection);
    this._table.setFocusedCell(0, selection, true);
    this.displayArticle(items[selection]);
  }
};


qx.Proto.displayArticle = function(item) {
  this._blogEntry.setArticle(item);
};


qx.Proto.finalize = function(e)
{
};

qx.Proto.close = function(e)
{
  // prompt user
  // e.returnValue = "[qooxdoo application: Do you really want to close the application?]";
};

qx.Proto.terminate = function(e)
{
  // alert("terminated");
};
