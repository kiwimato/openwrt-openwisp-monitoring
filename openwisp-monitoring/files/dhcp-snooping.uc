#!/usr/bin/ucode
// Learns the hostname and IP address of the wireless clients of this device from the
// DHCP and ARP traffic they exchange with the DHCP server of the network, for access
// points which do not run a DHCP server. Leases are written in dnsmasq format to the
// file read by netjson-monitoring (see dhcp.snooping_lease_file in dhcp.lua).
//
// Only frames seen on wireless interfaces are used: requests and ARP received from
// clients, and ACKs sent to clients which are already known. A kernel BPF filter
// keeps every other packet out of user space.
'use strict';
import * as socket from 'socket';
import { mkdir, readfile, rename, stat, writefile } from 'fs';

const LEASE_FILE = '/tmp/openwisp-monitoring/dhcp-snooping.leases';
// leases of a day are reported for clients which keep being active, also when
// the DHCP server hands out longer or infinite leases which are never renewed
const LEASE_TIME = 86400;
const KEEP = 7 * 86400;
const FLUSH_INTERVAL = 10;
const PACKET_OUTGOING = 4;
const ETH_P_IP = 0x0800, ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003;
const DHCP_DISCOVER = 1, DHCP_REQUEST = 3, DHCP_ACK = 5;
// classic BPF on the network layer (SOCK_DGRAM): ARP, or IPv4 UDP to port 67/68
const FILTER = [
	[ 0x28, 0, 0, 0xfffff000 ],                       // A = skb->protocol
	[ 0x15, 9, 0, ETH_P_ARP ], [ 0x15, 0, 9, ETH_P_IP ],
	[ 0x30, 0, 0, 9 ], [ 0x15, 0, 7, 17 ],            // UDP
	[ 0x28, 0, 0, 6 ], [ 0x45, 5, 0, 0x1fff ],        // not a fragment
	[ 0xb1, 0, 0, 0 ], [ 0x48, 0, 0, 2 ],             // A = UDP destination port
	[ 0x15, 1, 0, 67 ], [ 0x15, 0, 1, 68 ],
	[ 0x06, 0, 0, 0xffff ], [ 0x06, 0, 0, 0 ]
];

let leases = {}, dirty = false, wireless = {};

// socket.create() hands the protocol to socket(2) unchanged, which expects network
// byte order (bind() and recvmsg() convert it themselves). The byte order of this
// system is read from the ELF header of the interpreter (EI_DATA, 1 = little endian).
const little_endian = ord(readfile('/proc/self/exe', 6), 5) == 1;
function htons(value) {
	return little_endian ? ((value & 0xff) << 8) | (value >> 8) : value;
}

function is_wireless(ifname) {
	if (!(ifname in wireless))
		wireless[ifname] = stat(`/sys/class/net/${ifname}/phy80211`) != null;
	return wireless[ifname];
}

function mac_at(data, i) {
	return sprintf('%02x:%02x:%02x:%02x:%02x:%02x', ord(data, i), ord(data, i + 1),
		ord(data, i + 2), ord(data, i + 3), ord(data, i + 4), ord(data, i + 5));
}

function ip_at(data, i) {
	return sprintf('%d.%d.%d.%d', ord(data, i), ord(data, i + 1), ord(data, i + 2), ord(data, i + 3));
}

function load() {
	const now = time();
	for (let line in split(readfile(LEASE_FILE) ?? '', '\n')) {
		const field = split(line, ' ');
		if (length(field) >= 4 && +field[0] > now - KEEP)
			leases[field[1]] = { expiry: +field[0], ip: field[2], name: field[3] };
	}
}

function flush() {
	const now = time();
	let out = '';
	for (let mac, lease in leases) {
		if (lease.expiry < now - KEEP) {
			delete leases[mac];
			continue;
		}
		out += sprintf('%d %s %s %s *\n', lease.expiry, mac, lease.ip ?? '0.0.0.0', lease.name ?? '*');
	}
	mkdir(replace(LEASE_FILE, /\/[^\/]*$/, ''));
	writefile(`${LEASE_FILE}.tmp`, out);
	rename(`${LEASE_FILE}.tmp`, LEASE_FILE);
	dirty = false;
}

function update(mac, values) {
	const lease = leases[mac] ?? {};
	for (let key, value in values)
		if (value != null && lease[key] != value) {
			lease[key] = value;
			dirty = true;
		}
	leases[mac] = lease;
}

function parse_dhcp(data, outgoing) {
	const bootp = (ord(data, 0) & 15) * 4 + 8;
	if (length(data) < bootp + 240 || substr(data, bootp + 236, 4) != '\x63\x82\x53\x63')
		return;
	const mac = mac_at(data, bootp + 28), options = {};
	for (let i = bootp + 240; i < length(data);) {
		const code = ord(data, i);
		if (code == 255)
			break;
		if (code == 0) {
			i++;
			continue;
		}
		options[code] = substr(data, i + 2, ord(data, i + 1));
		i += 2 + ord(data, i + 1);
	}
	const type = options[53] ? ord(options[53], 0) : 0, now = time();
	if ((type == DHCP_REQUEST || type == DHCP_DISCOVER) && !outgoing) {
		let ip = ip_at(data, bootp + 12);
		if (ip == '0.0.0.0' && length(options[50]) == 4)
			ip = ip_at(options[50], 0);
		const name = options[12] ? replace(trim(options[12]), /[^A-Za-z0-9._-]/g, '-') : null;
		update(mac, {
			name: name || null,
			ip: ip != '0.0.0.0' ? ip : null,
			expiry: (leases[mac]?.expiry ?? 0) < now ? now + LEASE_TIME : null
		});
	}
	else if (type == DHCP_ACK && outgoing && leases[mac]) {
		let lease_time = LEASE_TIME;
		if (length(options[51]) == 4) {
			const o = options[51];
			lease_time = (ord(o, 0) << 24) | (ord(o, 1) << 16) | (ord(o, 2) << 8) | ord(o, 3);
		}
		const ip = ip_at(data, bootp + 16);
		update(mac, { ip: ip != '0.0.0.0' ? ip : null, expiry: now + min(lease_time, LEASE_TIME) });
	}
}

function parse_arp(data) {
	// Ethernet/IPv4 ARP only; a sender address of 0.0.0.0 is an address conflict probe
	if (length(data) < 28 || ord(data, 4) != 6 || ord(data, 5) != 4)
		return;
	const ip = ip_at(data, 14), now = time();
	if (ip == '0.0.0.0')
		return;
	const mac = mac_at(data, 8);
	update(mac, {
		ip: ip,
		expiry: (leases[mac]?.expiry ?? 0) < now + LEASE_TIME - 3600 ? now + LEASE_TIME : null
	});
}

const sock = socket.create(socket.AF_PACKET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK, htons(ETH_P_ALL));
if (!sock || !sock.setopt(socket.SOL_SOCKET, socket.SO_ATTACH_FILTER, { filter: FILTER }) ||
    !sock.bind({ family: socket.AF_PACKET, protocol: ETH_P_ALL, address: '00:00:00:00:00:00' }))
	die(`openwisp-monitoring-dhcp-snooping: cannot open packet socket: ${socket.error()}\n`);

load();
let flushed = time();
while (true) {
	const events = socket.poll(FLUSH_INTERVAL * 1000, [ sock, socket.POLLIN ]);
	if (events?.[0]?.[1]) {
		for (let msg = sock.recvmsg(1600); msg != null; msg = sock.recvmsg(1600)) {
			const address = msg.address;
			if (!address?.interface || !is_wireless(address.interface))
				continue;
			const outgoing = address.packet_type == PACKET_OUTGOING;
			if (address.protocol == ETH_P_ARP) {
				if (!outgoing)
					parse_arp(msg.data);
			}
			else
				parse_dhcp(msg.data, outgoing);
		}
	}
	if (dirty && time() - flushed >= FLUSH_INTERVAL) {
		flush();
		flushed = time();
	}
}
