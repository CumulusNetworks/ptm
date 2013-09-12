Prescriptive Topology Manager Daemon (ptmd)
===========================================

PTMD is a dynamic cabling verification tool to help eliminate cabling
errors in networks. It takes a graphviz-DOT specified network cabling
plan (something many operators already generate) and couples it with
runtime information derived from LLDP to verify that the cabling
matches the specification. The check is performed on every link
transition on each node in the network. PTMD runs as a Linux daemon.
