/^%/,//d
/^%%Title:/s/.$//
/^\/VM?/,/ VM?/c\
/VM? { pop } def
