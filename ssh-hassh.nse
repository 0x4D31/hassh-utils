local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

local openssl = stdnse.silent_require "openssl"
local ssh2 = stdnse.silent_require "ssh2"

description = [[
Reports hasshServer (i.e. SSH Server Fingerprint) and hasshServerAlgorithms for the target SSH server.
hasshServer = md5(kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms)
HASSH repo: https://github.com/salesforce/hassh

Credits: Ben Reardon, Adel Karimi, and JA3 crew
]]

---
-- @usage
-- nmap --script ssh-hassh target
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh-hassh: 
-- |   Server Identification String: SSH-2.0-libssh_0.7.0
-- |   hasshServer: 85a34ecc072b7fee11a05e8208ffc2a2
-- |_  hasshServer Algorithms: curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256;chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib,zlib@openssh.com

-- Used parts of the code from Kris Katterjohn's ssh2-enum-algos script
author = "Adel '0x4d31' Karimi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh")

-- Build and return the output table
local output = function(parsed)
  local out = stdnse.output_table()

  -- hasshServer
  local kexAlgs = parsed["kex_algorithms"]
  local encAlgs = parsed["encryption_algorithms_server_to_client"]
  local macAlgs = parsed["mac_algorithms_server_to_client"]
  local cmpAlgs = parsed["compression_algorithms_server_to_client"]
  local shkAlgs = parsed['server_host_key_algorithms']
  local hsa = { kexAlgs, encAlgs, macAlgs, cmpAlgs }
  local hasshServerAlgs = table.concat(hsa, ';')
  local hasshServer = stdnse.tohex(openssl.md5(hasshServerAlgs))
  out['Server Identification String'] = identificationString
  out['hasshServer'] = hasshServer
  out['hasshServer Algorithms'] = hasshServerAlgs
  -- Log other fields
  -- out['kex_algorithms'] = kexAlgs
  -- out['encryption_algorithms'] = encAlgs
  -- out['mac_algorithms'] = macAlgs
  -- out['compression_algorithms'] = cmpAlgs
  -- out['server_host_key_algorithms'] = shkAlgs

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

  status = sock:send("SSH-2.0-Nmap-SSH-HASSH\r\n")
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

  local status, response = ssh.receive_packet(sock)

  sock:close()

  if not status then
    return
  end

  local parsed = ssh.parse_kex_init(ssh.payload(response))

  return output(parsed)
end
