product samba
    id "Samba version 1.9.17p4"
    image sw
        id "Samba Execution Environment"
        version 0109170400
        order 0
        subsys base default
            id "Samba Execution Environment"
            replaces fw_samba.sw.base 0 9999999999
            replaces fw_samba.sw.samba 0 9999999999
            exp samba.sw.base
        endsubsys
    endimage
    image man
        id "Samba Online Documentation"
        version 0109170400
        order 1
        subsys manpages default
            id "Samba Man Page"
            replaces fw_samba.man.manpages 0 9999999999
            replaces fw_samba.man.samba 0 9999999999
            exp samba.man.manpages
        endsubsys
        subsys doc default
            id "Samba Documentation"
            replaces fw_samba.man.doc 0 9999999999
            exp samba.man.doc
        endsubsys
        subsys relnotes default
            id "Samba Release Notes"
            replaces fw_samba.man.relnotes 0 9999999999
            exp samba.man.relnotes
        endsubsys
    endimage
    image src
        id "Samba Source Code"
        version 0109170400
        order 2
        subsys samba
            id "Samba Source Code"
            replaces fw_samba.src.samba 0 9999999999
            exp samba.src.samba
        endsubsys
    endimage
endproduct
