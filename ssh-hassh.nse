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
-- nmap --script ssh-hassh --script-args 'database=file,client_string=string' <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh-hassh:
-- |   Server Identification String: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
-- |   hasshServer: b12d2871a1189eff20364cf5333619ee
-- |_  hasshServer Guess: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3 (49%) || SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6 (19%) || SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7 (4%) || SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4 (2%) || SSH-2.0-OpenSSH_7.9p1 Debian-10 (2%)

-- Used parts of the code from Kris Katterjohn's ssh2-enum-algos script
author = "Adel '0x4d31' Karimi and Daniel Roberson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh")

-- Build and return the output table
local output = function(parsed)
  local out = stdnse.output_table()

  local hasshdbfile = stdnse.get_script_args("database")
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

  -- hasshServer
  local kexAlgs = parsed["kex_algorithms"]
  local encAlgs = parsed["encryption_algorithms_server_to_client"]
  local macAlgs = parsed["mac_algorithms_server_to_client"]
  local cmpAlgs = parsed["compression_algorithms_server_to_client"]
  local shkAlgs = parsed["server_host_key_algorithms"]
  local hsa = { kexAlgs, encAlgs, macAlgs, cmpAlgs }
  local hasshServerAlgs = table.concat(hsa, ';')
  local hasshServer = stdnse.tohex(openssl.md5(hasshServerAlgs))
  out["Server Identification String"] = identificationString
  out["hasshServer"] = hasshServer

  -- Display matching hasshes
  local match = hasshdb[string.lower(hasshServer)]
  if match then
    out["hasshServer Guess"] = match
  else
    out["hassServer Guess"] = "Unknown."
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
