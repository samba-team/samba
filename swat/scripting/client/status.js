/*
	server status library for SWAT

	released under the GNU GPL Version 2 or later
*/


/* Ensure we always include the proper libs
   Playing with a way to add/del scripts on the fly...
*/
var lib = document.createElement('script');
lib.setAttribute('type', 'text/javascript');
lib.setAttribute('src', '/scripting/client/call.js');
var head = document.getElementsByTagName('head')[0];
head.appendChild(lib);

// Format for a server status table
var s = [
	{ id : "server",
	  label : "Server",
	  content: "text",
          defaultValue : "-",
          width : 100,
	},

	{ id : "status",
	  label : "Status",
	  content: "text",
	  defaultValue : "-",
	  width: 100,
	}
];

function __load_status_table(info, container)
{
	var table = new QxListView(s);
	var i;
	for (i in info) {
		table.addData( {server : i, status : info[i]} );
	}
	container.add(table);
	container.setVisible(true);
}

function getServerStatus(container) 
{
	server_call_url("/scripting/server/status.esp", 'serverInfo',
				function(info) { __load_status_table(info, container); });
}
