======
ptmctl
======

-----------------------------------------
Retrieve Operational State of ptmd Daemon
-----------------------------------------

:Author: Cumulus Networks, Inc
:Date:   2016-04-01
:Copyright: Copyright 2014 Cumulus Networks, Inc.  All rights reserved.
:Version: 3.0
:Manual section: 8

SYNOPSIS
========

    **ptmctl [-hlb] [-d] [-j] [--bfd_clients [CLIENT]] [--bfd_client_sess]**

DESCRIPTION
===========

    **ptmctl** retrieves operational state about configured ports, BFD sessions
    from ptmd.

OPTIONS
========

    -h, --help            Show a usage summary.

    -d, --details         Show detailed information for a particular command

    -l, --lldp            Show per port LLDP information (active sessions).

    -b, --bfd             Show BFD session information.

    -j, --json            Format the output in JSON.
    --bfd_client_sess     Show BFD sessions started by clients.
    --bfd_clients         Show list of clients who started BFD sessions.

EXAMPLES
========

    # print a line summary of all configured ports

        **ptmctl**

    # print detailed line information of all configured ports

        **ptmctl -d**

    # print active BFD sessions

        **ptmctl -b**

    # print active LLDP sessions

        **ptmctl -l**

    # print detailed information of all configured ports in JSON format

        **ptmctl -j**

    # print active BFD sessions in JSON format

        **ptmctl -b -j**

    # get the list of client sessions

        **ptmctl --bfd_client_sess**

    # get the list of all client(s)

        **ptmctl --bfd_clients**

    # get the list of a specific client "cumulus"

        **ptmctl --bfd_clients cumulus**

    # Typical error outputs

        **ERR: Topology file error [/etc/ptm.d/topology.dot] [errno 9] -**
        **please check /var/log/ptmd.log for more info**

        **ERR: No Hostname/MgmtIP found [Check LLDPD daemon status] -**
        **please check /var/log/ptmd.log for more info**

        **ERR: No BFD sessions . Check connections**

        **ERR: No BFD clients - please check /var/log/ptmd.log for more info**

        **ERR: No client BFD sessions - please check /var/log/ptmd.log for more info**

        **Unsupported command**

SEE ALSO
========

    ptmd(8)
