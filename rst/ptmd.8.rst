====
ptmd
====

-----------------------------------
Prescriptive Topology Module Daemon
-----------------------------------

:Author: Cumulus Networks, Inc.
:Date:   2017-12-05
:Copyright: Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
:Version: 3.0
:Manual section: 8

SYNOPSIS
========
    **ptmd [-dh] [-c TOPOLOGY-FILE] [-l <CRIT | ERR | WARN | INFO | DEBUG>]**


DESCRIPTION
===========
    **ptmd** performs the following tasks:

        # Topology verification using LLDP

        # Forwarding path failure detection using BFD

        # Client management

        # Command / response

        # Event notifications

        # User configuration via topology file

        # Specifying BFD parameters via client API

    **ptmd** accepts a topology file that specifies the prescribed
    physical, connected topology (a.k.a cabling) using the DOT language.
    The user can specify parameters in the DOT file that control some
    of the behaviors of **ptmd**. The parameters can operate at the node (or edge)
    level and graph (or network) level.

    **ptmd** also allows for BFD sessions to be started/stopped via
    Client APIs.

    # Topology verification using LLDP

        **ptmd** verifies the actual physical connections in the network
        against a prescribed topology.  **ptmd** creates a client connection
        to the LLDP daemon, **lldpd**, to retrieve the neighbor relationship
        between nodes in the network and compares that with the prescribed
        topology information.

        It also registers for future notifcations from **lldpd** so that it can
        compare the current **lldpd** state with its topology file.

        Currently **ptmd** compares the PortId IfName of the neighbor with the
        port name specified in the topology file. The IfName is retrieved using
        the information provided by **lldpd**. **ptmd** also provides the option
        of comparing using PortDescr instead of ifName. This is achieved by
        setting the LLDP parameter "match_type=portdescr" globally or 
        per-port

        NB: **ptmd** is only supported on physical interfaces like swpXX. Logical
        interfaces like bonds and VLANs are not supported at this point.

    # Forwarding path failure detection using BFD

        **ptmd** supports BiDirectional Forwarding Detection protocol
        (v1 / RFC 5880/5883).
        BFD is a protocol intended to detect faults in the bidirectional path
        between two forwarding engines, including interfaces, data link(s), and
        to the extent possible the forwarding engines themselves, with potentially
        very low latency. **ptmd** supports both singlehop and multihop BFD.

        Singlehop BFD establishes a session between two endpoints over a
        particular link. These sessions can be enabled via the
        topology file or via the new client APIs. For a singlehop BFD session,
        **ptmd** waits for the kernel IP neighbor table to be populated with an IP
        address and uses this IP address to send BFD packets to.

        Multihop BFD establishes a session between a local and remote IP. These
        sessions *cannot* be enabled via the topology file and require the new client
        APIs.

        BFD echo mode is also supported. Echo mode is enabled by adding the echoSupport
        param in the topology file.

        IPv4 and IPv6 BFD is supported.

        NB: BFD Demand mode is not supported in this release

    # Client management

        **ptmd** creates an abstract named socket (/var/run/ptmd.socket)
        on startup. Other applications can connect to this socket to receive
        notifications and send commands.

    # Command / response

        **ptmd** can receive commands sent over the client socket. The commands have
        to be in arranged in a CSV format.

        **ptmd** expects the client messages to be in CSV style.
        The format is described below.

            Row1 = [data len, version = 2, type, cmdid, client-name]

            Row2 = [Hdr1,  Hdr2,  Hdr3,...,  HdrN]

            Row3 = [Data1, Data2, Data3,..., DataN]

            Row4 = [data len, version = 2, type, cmdid, client-name]

            Row5 = [Hdr1,  Hdr2,  Hdr3,...,  HdrN]

            Row6 = [Data1, Data2, Data3,..., DataN]
            ..
            ..
            ..

            RowM = [Data1, Data2, Data3,..., DataN]

        The client would have to parse/build the message stream as CSV.
        Please look at **ptmctl** to get a better understanding of how
        to parse/build this data.

        The list of commands supported by **ptmd**

        # cmd : get-status

          args: module ["lldp" | "bfd"]

          args: detail ["yes" | "no"]

            If no module is specified, returns information for every port
            configured via the topology file.
            If module is "lldp", then the active lldp sessions are reported.
            If module is "bfd", then the active BFD sessions are reported.
            If detail is "yes", then additional information is reported.

          NB: **ptmd** supports this command (without options) in the
          plain string for backward compatibility reasons.

        # cmd : get-bfd-client

          args: sessions ["yes"]

          args: client   [client name]

            No arguments - Returns the list of clients having BFD sessions.
            If sessions is "yes", returns the list of client BFD sessions.
            If client name is specified, filters information for that client.

    # Event notifications

        **ptmd** constantly monitors its LLDP and BFD neighbor states to
        perform its topology and forwarding path checks. If a check fails
        or passes for a particular port, it will take the following actions:

        # Log the result

            **ptmd** will log these events in its log file.

        # Run user-specified action scripts

            #Topology based events

            **ptmd** calls **if-topo-pass** or **if-topo-fail**, based on 
            whether LLDP and/or BFD check passed or failed for ports configured
            via the topology file. Its possible to have the LLDP check fail
            while the BFD check pass, or vice-versa.
            The two events are not co-related. It is possible that the action 
            scripts will get called multiple times for the same event 
            (For e.g..  link down), since LLDP and BFD will detect them 
            independently.

            #BFD session events

            **ptmd** calls **bfd-sess-up** or **bfd-sess-down**, based on
            whether BFD session went up or down.

            The way to get the event information in the scripts is via
            shell environment variables that are set with the appropriate
            event information and are accessible within the respective scripts

            **if-topo-pass** / **if-topo-fail**

            $PTM_PORT       : PTM port

            $PTM_CBL        : Cable check status ["pass", "fail"]

            $PTM_EXPNBR     : Expected Neighbor edge information

            $PTM_ACTNBR     : Actual Neighbor edge information

            $PTM_BFDSTATUS  : BFD status ["N/A", "pass", "fail"]

            $PTM_BFDPEER    : BFD peer IP

            $PTM_BFDLOCAL   : BFD local IP

            $PTM_BFDTYPE    : BFD type ["multihop", "singlehop"]

            **bfd-sess-up** / **bfd-sess-down**

            $PTM_PORT       : PTM port

            $PTM_BFDSTATUS  : BFD status ["N/A", "pass", "fail"]

            $PTM_BFDPEER    : BFD peer IP

            $PTM_BFDLOCAL   : BFD local IP

            $PTM_BFDTYPE    : BFD type ["multihop", "singlehop"]

            $PTM_BFDVRF     : BFD VRF name (if applicable)

        # Notify any connected clients

            **ptmd** will notify any of the connected clients about this event.
            The event string is the same as the output of **get-status** command
            (CSV format described above).

    # User configuration via topology file

        **ptmd** allows for users to configure some parameters using the
        topology file.
        The parameters are classified as Host only, Global, Per-Port (Node) and
        Templates:

        # Host-only

            Host-only parameters allow us to specify configuration options
            that impact the self node/host only.

            # hostnametype

                Configures the hostname check to be FQDN or hostname based
                when **ptmd** is looking for the hostname in the topology
                file.

        # Global

            Global parameters are applied to all the nodes in the
            topology file. Currently two global parameters exist,
            LLDP and BFD:

            # LLDP

                Configures global LLDP parameters and applies them
                to all ports. By default LLDP is enabled and if no
                keyword is present, then default values are used
                on all ports. There is no way to disable LLDP today.

            # BFD

                Configures global BFD parameters and applies them to
                all ports. If the keyword is not present, then the feature
                is considered disabled (unless there is a per-port
                override).

        # Per-Port

            Per-port parameters allow finer grain control. They override any
            compiled or global defaults.

        # Templates

            Templates allow flexibilty in choosing different parameter
            combinations and apply them to a port. A template is a special
            parameter that tells **ptmd** to reference a "named" parameter
            string, rather than the default ones.

            There are currently two template keywords - bfdtmpl and lldptmpl:

            # bfdtmpl

                Specifies a custom parameter tuple for BFD.

            # lldptmpl

                Specifies a custom parameter tuple for LLDP.

    # Specifying BFD parameters via client API

        **ptmd** now allows BFD sessions to be started / stopped via
        Client APIs. This is how multihop BFD sessions are started.
        Clients can supply BFD session parameters using this API

    # Supported parameters and values

        The following parameters and values are supported by **ptmd** via
        the topology file.

        # Host-only

            hostnametype  [Default hostname, <hostname, fqdn>]

        # BFD

            upMinTx         [Default is 300ms, specified in ms.]

            requiredMinRx   [Default is 300ms, specified in ms.]

            detectMult      [Default is 3.]

            echoMinRx       [Default is 50, min 50ms]

            slowMinTx       [Default is 2000ms, specified in ms.]

            afi             [Default is v4, <v4, v6, both>]

            echoSupport     [Default is 0 (disabled), < 0, 1>]

        # LLDP

            match_type      [Default ifname, <ifname, portdescr>]

            match_hostname  [Default hostname, <hostname, fqdn>]

        The following parameters and values are supported by **ptmd** via
        the client API for BFD sessions

        # srcIPaddr  - Source IP addr

        # dstIPaddr  - Destination IP addr

        # multihop   - Multihop BFD session

        # ifName     - Interface name for singlehop BFD session

        # client     - Client name to identify the session

        # seqid      - Client Id to help identify client sessions

        # maxHopCnt  - Max hop count for multihop sessions [Default 5]

        # sendEvent  - force send first session down/up event [Default 0]

        ovsdb schema 1.3 specific parameters

        # vnid             - VNID to be used, default 0

        # local_dst_mac    - Local destination mac

        # local_dst_ip     - Local destination IP

        # remote_dst_mac   - Remote destination mac

        # remote_dst_ip    - Remote destination IP

        # decay_min_rx     - Decay Min Rx

        # fowarding_if_rx  - Keep forwarding if receiving packets

        # cpath_down       - Control path down

        # check_tnl_key    - Check tunnel key

    # Examples of different parameters and their usage via topology file

        # Example 1

            **ptmd** will ignore the FQDN and
            only look for "switch04", since that is the hostname of the switch
            it’s running on:

            ::

                graph G {
                hostnametype="hostname"
                BFD="upMinTx=150,requiredMinRx=250"
                "cumulus":swp44 -- "switch04.cumulusnetworks.com":swp20
                "cumulus":swp46 -- "switch04.cumulusnetworks.com":swp22
                }

        # Example 2

            FQDN style matching for host "switch05.cumulusnetworks.com"

            ::

                graph G {
                hostnametype="fqdn"
                "cumulus":swp44 -- "switch05.cumulusnetworks.com":swp2
                "cumulus":swp46 -- "switch05.cumulusnetworks.com":swp4
                }

        # Example 3

            FQDN style matching for host "sw1.domain.com".
            LLDP enabled globally, matching on port description.
            BFD enabled globally, with defaults.

            ::

                graph G {
                hostnametype="fqdn"
                BFD="default"
                LLDP="match_type=portdescr"
                "sw1.domain.com":"swp1" -- "switch2":"port 41"
                }

        # Example 4

            LLDP enabled globally, matching on FQDN of neighbor "switch2.domain.com".
            BFD enabled globally, with detect multiplier as 4.

            ::

                graph G {
                BFD="detectMult=4"
                LLDP="match_hostname=fqdn"
                "sw1.domain.com":"swp1" -- "switch2.domain.com":"swp41"
                }

        # Example 5

            BFD enabled globally with detectMult=4.
            BFD enabled on the edges with different session params.

            ::

                graph G {
                BFD="detectMult=4"
                "sw1":swp4 -- "sw4":swp2 [BFD="upMinTx=150,requiredMinRx=250"]
                "sw1":swp5 -- "sw4":swp3 [BFD="upMinTx=250,requiredMinRx=350"]
                "sw1":swp6 -- "sw4":swp4
                }


OPTIONS
========

    -c TOPOLOGY-FILE        Parse the specified DOT topology file and build
                            the corresponding network topology.

    -d                      Run as a daemon.

    -h                      Show a short usage summary.

    -l <CRIT | ERR | WARN | INFO | DEBUG>
                            Set log level to log into ptmd.log.

FILES
=====

    # **/etc/ptm.d/topology.dot**

        Default prescribed topology DOT file.

    # **/etc/ptm.d/if-topo-pass**

        Script to invoke on a match between actual connection and prescribed
        connection.

    # **/etc/ptm.d/if-topo-fail**

        Script to invoke if the actual connection and prescribed connection
        do not match.

    # **/etc/ptm.d/bfd-sess-up**

        Script to invoke if a BFD session came up

    # **/etc/ptm.d/bfd-sess-down**

        Script to invoke if a BFD session went down

SERVICE OPTIONS
===============

    **ptmd** provides the following options via the **systemctl** command

    # **enable** / **disable**

        Enable or Disable the **ptmd** service.

    # **start** / **stop** / **restart**

        Start, Stop or Restart the **ptmd** service.

    # **reload**

        Signals **ptmd** to read the **topology.dot** file again without restarting.
        Applies the new configuration (if any) to the current running state.

    # **status**

        Retrieves current running state of **ptmd**.

UPGRADE NOTES
=============

    This version of **ptmd** has a new CSV message format. **ptmctl** has been
    upgraded to use the new format as well.

SEE ALSO
========

    ptmctl(8)
