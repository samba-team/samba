/*
	client side js functions for registry editing

	Copyright Andrew Tridgell 2005
	released under the GNU GPL Version 2 or later
*/

function __folder_list(fParent, list) 
{
	var i;
	fParent.removeAll();
	for (i=0;i<list.length;i++) {
		var fChild;
		fChild = new QxTreeFolder(list[i]);
		fParent.add(fChild);
		fChild.binding = fParent.binding;
		if (fParent.reg_path == '\\') {
			fChild.reg_path = list[i];
		} else {
			fChild.reg_path = fParent.reg_path + '\\' + list[i];
		}
		fChild.add(new QxTreeFolder('Working ...'));
		fChild.addEventListener("click", function() { 
			var el = this; __folder_click(el); 
		});
		fParent.setOpen(1);
	}
}

function __folder_click(node) 
{
	if (!node.populated) {
		node.populated = true;
		server_call_url("/scripting/server/regedit.esp", 'enum_path', 
				function(list) { __folder_list(node, list); }, 
				node.binding, node.reg_path);
	}
}

/* return a registry tree for the given server */
function __registry_tree(binding) 
{
	var tree = new QxTree("registry: " + binding);
	tree.binding = binding;
	tree.reg_path = "\\";
	tree.populated = false;
	with(tree) {
		setBackgroundColor(255);
		setBorder(QxBorder.presets.inset);
		setOverflow("scroll");
		setStyleProperty("padding", "2px");
		setWidth("100%");
		setHeight("90%");
		setTop("10%");
	}
	tree.addEventListener("click", function() { 
		var el = this; __folder_click(el); 
	});
	return tree;
}

/*
  create a registry editing widget and return it as a object

*/
function regedit_widget(binding) 
{
	var regedit = new QxWindow("Registry Editor");
	regedit.setSpace(300, 600, 300, 600);

	var fieldSet = new QxFieldSet();

	regedit.binding = binding;

	with(fieldSet) {
		setWidth("100%");
		setHeight("100%");
	};

	var gl = new QxGridLayout("auto,auto,auto,auto,auto", "100%");
	gl.setEdge(0);
	gl.setCellPaddingTop(3);
	gl.setCellPaddingBottom(3);

	regedit.add(fieldSet);

	var t = __registry_tree(regedit.binding);

	function change_binding(e) {
		regedit.binding = e.getNewValue();
		srv_printf("changed binding to %s\\n", regedit.binding);
		gl.remove(t);
		t = __registry_tree(regedit.binding);
		gl.add(t, { row : 2, col : 1 });
	}

	var b = new QxTextField(regedit.binding);
	b.addEventListener("changeText", change_binding);

	gl.add(b, { row : 1, col : 1 });
	gl.add(t, { row : 2, col : 1 });
	
	fieldSet.add(gl);
	regedit.add(fieldSet);

	/* 
	   call the startup() method to display the widget
	*/
	regedit.startup = function() {
		this.setVisible(true);
		this.setMoveable(true);
		this.setResizeable(true);
		this.setResizeMethod("frame");
		this.setMoveable(true);
	}

	return regedit;
};
