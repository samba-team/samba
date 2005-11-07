while(<>) {
    chomp();
    @le = split '\s+',$_,5;
    $ln = $le[4];
    $cname = $le[3]; 
    $outstr = sprintf "TMG: %d\nTMW: %d\nEID: 1000\nETP: INFO\nECT: 0\nRS2: 0\nCRN: 0\nUSL: 0\nSRC: Syslog\nSRN: $cname\nSTR: $ln\nDAT:\n\n",time(),time();
    print $outstr;
}
