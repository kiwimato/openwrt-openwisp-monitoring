-- retrieve dhcp leases
local utils = require('openwisp-monitoring.utils')
local uci = require('uci')
local uci_cursor = uci.cursor()
local io = require('io')
local dhcp = {}

function dhcp.parse_dhcp_lease_file(path, leases)
  local f = io.open(path, 'r')
  if not f then return leases end
  for line in f:lines() do
    local expiry, mac, ip, name, id = line:match('(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)')
    local lease = {expiry = tonumber(expiry), mac = mac, ip = ip, client_name = name, client_id = id}
    if not utils.is_table_empty(lease) then table.insert(leases, lease) end
  end

  return leases
end

-- written by openwisp-monitoring-dhcp-snooping on devices which do not run a DHCP server
dhcp.snooping_lease_file = '/tmp/openwisp-monitoring/dhcp-snooping.leases'

function dhcp.get_dhcp_leases()
  local dhcp_configs = uci_cursor:get_all('dhcp')
  local leases = {}
  if not utils.is_table_empty(dhcp_configs) then
    for _, config in pairs(dhcp_configs) do
      if config and config['.type'] == 'dnsmasq' and config.leasefile then
        leases = dhcp.parse_dhcp_lease_file(config.leasefile, leases)
      end
    end
  end
  -- snooped leases only add clients which the local DHCP server does not know
  local known = {}
  for _, lease in ipairs(leases) do known[lease.mac] = true end
  for _, lease in ipairs(dhcp.parse_dhcp_lease_file(dhcp.snooping_lease_file, {})) do
    if not known[lease.mac] then table.insert(leases, lease) end
  end
  if utils.is_table_empty(leases) then return nil end
  return leases
end

return dhcp
