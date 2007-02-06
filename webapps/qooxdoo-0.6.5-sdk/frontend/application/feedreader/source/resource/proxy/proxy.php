<?php

$ALLOWED_URL_PREFIXES = array(
    "http://feeds.feedburner.com",
    "http://blog.dojotoolkit.org/feed",
    "http://www.jackslocum.com/blog/feed/",
    "http://portlets.blogspot.com",
    "http://www.go-mono.com/monologue/index.rss",
    "http://feeds.yuiblog.com/YahooUserInterfaceBlog",
);

$ALLOWED_URL_SUFFIXES = array(
    ".rdf",
    ".rss",
    "atom.xml",
    "rss2",
    "rss.xml",
    "feed/atom/",
);

$proxy_url = isset($_GET['proxy']) ? $_GET['proxy'] : false;

if (!$proxy_url) {
    header("HTTP/1.0 400 Bad Request");
    echo "proxy.php failed because proxy parameter is missing";
    exit();
}

$is_url_valid = false;
foreach ($ALLOWED_URL_PREFIXES as $prefix) {
    if (strpos($proxy_url, $prefix) === 0) {
        $is_url_valid = true;
        break;
    }
}

foreach ($ALLOWED_URL_SUFFIXES as $suffix) {
    if (strpos($proxy_url, $suffix) === strlen($proxy_url)-strlen($suffix)) {
        $is_url_valid = true;
        break;
    }
}

if (!$is_url_valid) {
    header("HTTP/1.0 400 Bad Request");
    echo "Address is not allowed!";        
    exit();
}

$session = curl_init($proxy_url);

curl_setopt($session, CURLOPT_HEADER, false);
curl_setopt($session, CURLOPT_RETURNTRANSFER, true);

header("Content-Type: application/xml");
echo(curl_exec($session));

curl_close($session);

?>