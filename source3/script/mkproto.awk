# generate prototypes for Samba C code
# tridge, June 1996

BEGIN {
  inheader=0;
}

{
  if (inheader) {
    if (match($0,"[)][ \t]*$")) {
      inheader = 0;
      printf "%s;\n",$0;
    } else {
      printf "%s\n",$0;
    }
    next;
  }
}

/^static|^extern/ || !/^[a-zA-Z]/ || /[;]/ {
  next;
}

!/^unsigned|^mode_t|^DIR|^user|^int|^char|^uint|^struct|^BOOL|^void|^time/ {
  next;
}


/[(].*[)][ \t]*$/ {
    printf "%s;\n",$0;
    next;
}

/[(]/ {
  inheader=1;
  printf "%s\n",$0;
  next;
}

