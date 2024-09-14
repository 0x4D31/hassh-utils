local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local datafiles = require "datafiles"

local openssl = stdnse.silent_require "openssl"
local ssh2 = stdnse.silent_require "ssh2"

description = [[
Reports hasshServer (i.e. SSH Server Fingerprint) and hasshServerAlgorithms for the target SSH server. Compares reported hasshServer with a local database of known fingerprints.
hasshServer = md5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
HASSH repo: https://github.com/salesforce/hassh

Credits: Ben Reardon, Adel Karimi, and JA3 crew
]]

---
-- @usage
-- nmap --script ssh-hassh --script-args 'database=file,client_string=string,skip_hasshdb' <target>
--
-- @output
--
-- PORT   STATE SERVICE VERSION
-- 22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
-- | ssh-hassh:
-- |   hasshServer: a65c3b91f743d3f246e72172e77288f1
-- |   Server Identification String: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
-- |   hasshServer Guess:            SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3 (100+)
-- |                             --> SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2 (54)
-- |                                 SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6 (22)
-- |                                 SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7 (15)
-- |                                 SSH-2.0-OpenSSH_9.2p1 (7)
-- |                                 SSH-2.0-OpenSSH_9.3 (3)
-- |                                 SSH-2.0-OpenSSH_9.5 FreeBSD-20240806 (1)
-- |_                                SSH-2.0-OpenSSH_9.5 (1)

-- Used parts of the code from Kris Katterjohn's ssh2-enum-algos script
author = "Adel '0x4d31' Karimi and Daniel Roberson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh")

-- Build and return the output table
local output = function(parsed)
  local out = stdnse.output_table()

  local hasshdbfile
  local skip_hasshdb = stdnse.get_script_args("skip_hasshdb")
  if not skip_hasshdb then
    -- Initialize hasshdb
    hasshdbfile = stdnse.get_script_args("database")
    if not hasshdbfile then
      hasshdbfile = "nselib/data/hasshdb"
    else
      hasshdbfile = "nselib/data/" .. hasshdbfile
    end
    stdnse.debug1("Using database file: %s", hasshdbfile)

    status, hasshdb = datafiles.parse_file(hasshdbfile, {["^%s*([^%s# ]+)[%s ]+"] ="^%s*[^%s# ]+[%s ]+(.*)"})
    if not status then
      stdnse.debug1("Could not open hassh database: %s", hasshdbfile)
      return
    end
  end

  -- hasshServer
  local kexAlgs = parsed["kex_algorithms"]
  local encAlgs = parsed["encryption_algorithms_server_to_client"]
  local macAlgs = parsed["mac_algorithms_server_to_client"]
  local cmpAlgs = parsed["compression_algorithms_server_to_client"]
  local shkAlgs = parsed["server_host_key_algorithms"]
  local hsa = { kexAlgs, encAlgs, macAlgs, cmpAlgs }
  local hasshServerAlgs = table.concat(hsa, ';')
  local hasshServer = stdnse.tohex(openssl.md5(hasshServerAlgs))
  out["hasshServer"] = hasshServer
  out["Server Identification String"] = identificationString

  -- Query hasshdb and display results
  if not skip_hasshdb then
    local match = hasshdb[string.lower(hasshServer)]
    if match then
      local guess = match:gsub(" || ", "\n                                ")
      local escapedIdentificationString = identificationString:gsub("%p", "%%%1")
      guess = guess:gsub(escapedIdentificationString, "--> " .. identificationString)
      guess = "           " .. guess .. " "
      local escapedArrow = string.gsub("    -->", "%p", "%%%1")
      guess = guess:gsub(escapedArrow, "-->")
      out["hasshServer Guess"] = guess
      if not string.find(guess, " --> ") then
        out["hasshServer Warning"] = "hasshServer does not match any Server Identification strings within " .. hasshdbfile ..". Please report hasshServer and Server Identification String to the developers."
      end
    else
      out["hasshServer Guess"] = "Unknown. Please report hasshServer and Server Identification String to the developers."
    end
  end

  -- Display algorithms if verbosity is set
  if nmap.verbosity() == 2 then
    out["hasshServer Algorithms"] = hasshServerAlgs
  end

  -- Display these if extra verbosity is set (-vv)
  if nmap.verbosity() > 2 then
    out['kex_algorithms'] = kexAlgs
    out['encryption_algorithms'] = encAlgs
    out['mac_algorithms'] = macAlgs
    out['compression_algorithms'] = cmpAlgs
    out['server_host_key_algorithms'] = shkAlgs
  end

  return out
end

action = function(host, port)
  local sock = nmap.new_socket()
  local status = sock:connect(host, port)

  if not status then
    return
  end

  status, data = sock:receive_lines(1)
  if not status then
    sock:close()
    return
  else
    -- Server Identification String
    tmp = string.gsub(data, "\x0D", "")
    identificationString = string.gsub(tmp, "\x0A", "")
  end

  -- Send client identification string
  local clientstring = stdnse.get_script_args("client_string")
  if not clientstring then
    clientstring = "SSH-2.0-Nmap-SSH-HASSH"
  end

  local s, e = string.find(clientstring, "SSH")
  if s ~= 1 then
    stdnse.debug("Invalid client string: %s", clientstring)
    return
  end
  stdnse.debug1("Using client string: %s", clientstring)

  status = sock:send(clientstring .. "\r\n")
  if not status then
    sock:close()
    return
  end

  local ssh = ssh2.transport

  local pkt = ssh.build(ssh.kex_init())

  status = sock:send(pkt)
  if not status then
    sock:close()
    return
  end

  -- Receive algorithms
  local status, response = ssh.receive_packet(sock)

  sock:close()

  if not status then
    return
  end

  local parsed = ssh.parse_kex_init(ssh.payload(response))
  return output(parsed)
end
