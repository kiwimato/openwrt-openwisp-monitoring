DHCP Snooping
=============

OpenWISP Monitoring shows the hostname and IP address of WiFi clients
using the DHCP leases sent by the monitoring agent. Devices running a DHCP
server (dnsmasq) report their own leases, but access points which leave
DHCP to another device of the network (e.g. a router or a firewall) have
none to report.

The optional ``openwisp-monitoring-dhcp-snooping`` package fills this gap:
it learns the hostname and IP address of the wireless clients of the
device from the DHCP and ARP traffic they exchange with the network and
adds them to the DHCP leases sent to OpenWISP Monitoring.

Installation
------------

Install the package alongside ``openwisp-monitoring``:

.. code-block:: shell

    apk add openwisp-monitoring-dhcp-snooping

The service starts right away and at every boot; to stop using it, remove
the package.

How it Works
------------

The ``openwisp-monitoring-dhcp-snooping`` service opens a packet socket
with a kernel filter which only lets ARP packets and DHCP messages reach
it, and only uses those seen on the wireless interfaces of the device:

- DHCP requests sent by clients provide their hostname and IP address;
- DHCP acknowledgements sent to clients update their IP address;
- ARP packets sent by clients keep their IP address up to date, which is
  important when the DHCP server hands out very long leases, because
  clients then rarely send DHCP messages after joining the network.

The learned leases are stored in
``/tmp/openwisp-monitoring/dhcp-snooping.leases`` (in the dnsmasq lease
format) and are reported only for clients which the local DHCP server of
the device does not already know.

.. note::

    The hostname of a client becomes known only after it sends a DHCP
    request, which usually happens when it joins the WiFi network, while
    its IP address is learned within minutes from its ARP traffic.
