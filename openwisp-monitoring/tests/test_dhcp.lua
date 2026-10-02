package.path = package.path .. ";../files/lib/openwisp-monitoring/?.lua;../files/sbin/?.lua"

local cjson = require('cjson')
local luaunit = require('luaunit')
local dhcp_data = require('test_files/dhcp_data')

local snooping_enabled = false

local dhcp_open = function(arg)
  local test_file_dir = './test_files/'
  if arg == '/tmp/dhcp.leases' then
    return io.open(test_file_dir .. 'dhcp_leases.txt')
  elseif arg == '/tmp/dhcp.leases.irregular' then
    return io.open(test_file_dir .. 'dhcp_leases_irregular.txt')
  elseif arg == '/tmp/openwisp-monitoring/dhcp-snooping.leases' and snooping_enabled then
    return io.open(test_file_dir .. 'dhcp_snooping_leases.txt')
  else
    return nil
  end
end

TestDhcp = {
  setUp = function()
    local env = require('main_env')
    package.loaded.uci = env.uci
    package.loaded.io = env.io
    package.loaded.io.open = dhcp_open
  end,
  tearDown = function()
    snooping_enabled = false
    package.loaded.dhcp = nil
  end
}

TestNetJSON = {
  setUp = function()
    local env = require('basic_env')
    package.loaded.ubus = env.ubus
    package.loaded.io = {
      popen = function(arg)
        local f = assert(io.tmpfile())
        if arg == 'cat /proc/loadavg' then
          f:write('0.37 0.95 1.23 2/873 56899\n')
        else
          f:write('')
        end
        f:seek('set', 0)
        return f
      end,
      open = dhcp_open,
      write = function(...)
        return nil
      end
    }
    package.loaded.uci = {
      cursor = function()
        return {
          get_all = function(...)
            local arg = {...}
            if arg[2] == 'dhcp' then
              return dhcp_data.config
            else
              return nil
            end
          end,
          get = function(...)
            return nil
          end,
          foreach = function(...)
            return nil
          end
        }
      end
    }
  end,
  tearDown = function()
  end
}

function TestDhcp.test_dhcp_leases()
  local dhcp_functions = require('dhcp')

  luaunit.assertEquals(dhcp_functions.get_dhcp_leases(), dhcp_data.leases)
  luaunit.assertEquals(dhcp_functions.parse_dhcp_lease_file('/tmp/dhcp.leases', {}), dhcp_data.leases)
  luaunit.assertEquals(dhcp_functions.parse_dhcp_lease_file('/tmp/no_dhcp.leases', {}), {})
end

function TestNetJSON.test_dhcp()
  local netjson_string = require('netjson-monitoring')
  local netjson = cjson.decode(netjson_string)
  luaunit.assertEquals(netjson["dhcp_leases"][1]["mac"], "e8:6a:64:3e:4a:3c")
  luaunit.assertEquals(netjson["dhcp_leases"][1]["client_id"], "01:e8:6a:64:3e:4a:3c")
  luaunit.assertEquals(netjson["dhcp_leases"][1]["ip"], "192.168.1.136")
  luaunit.assertEquals(netjson["dhcp_leases"][1]["expiry"], 1620788343)
end

function TestDhcp.test_dhcp_leases_irregular()
  local dhcp_functions = require('dhcp')
  local expected = {
    {
      client_id = "01:c6:df:44:00:00:00",
      client_name = "*",
      expiry = 1705556643,
      ip = "192.168.1.163",
      mac = "c6:df:44:00:00:00"
    }
  }
  local parsed = dhcp_functions.parse_dhcp_lease_file('/tmp/dhcp.leases.irregular', {})
  luaunit.assertEquals(parsed, expected)
end

function TestDhcp.test_dhcp_snooping_leases()
  snooping_enabled = true
  local dhcp_functions = require('dhcp')
  local snooped = {
    client_id = "*",
    client_name = "Pixel-6a",
    expiry = 1620790000,
    ip = "192.168.1.150",
    mac = "52:7e:b1:d3:5e:10"
  }
  luaunit.assertEquals(dhcp_functions.get_dhcp_leases(), {dhcp_data.leases[1], snooped},
    'snooped leases must be added after the dnsmasq ones, which win for the same MAC')
  package.loaded.uci = {
    cursor = function()
      return {
        get_all = function()
          return nil
        end
      }
    end
  }
  package.loaded.dhcp = nil
  dhcp_functions = require('dhcp')
  luaunit.assertEquals(dhcp_functions.get_dhcp_leases()[2], snooped,
    'snooped leases must be reported when no local DHCP server is configured')
  snooping_enabled = false
  luaunit.assertEquals(dhcp_functions.get_dhcp_leases(), nil)
end

os.exit(luaunit.LuaUnit.run())
