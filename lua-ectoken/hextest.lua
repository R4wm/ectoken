#!/usr/local/bin/luajit-2.0.5
local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat

local function hex(str,spacer)
    return (gsub(str,"(.)", function (c)
        return format("%02X%s", byte(c), spacer or "")
    end))
end


local aes = require "resty.nettle.aes"

local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
local ciphertext, digest = aes256:encrypt("Thisi s somefunkystuff")
print("aes256 gcm enc", #ciphertext, hex(ciphertext))
print("aes256 gcm dgst", #digest, hex(digest))
local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
local plaintext, digest = aes256:decrypt(ciphertext)
print("aes256 gcm dec", #plaintext, plaintext)
print("aes256 gcm dgst", #digest, hex(digest))
    
print("no hex cipher --> "..ciphertext)
print("no hex digest --> "..digest)

print("Doing base 64 stuff")
local base64 = require "resty.nettle.base64"
local encoded = base64.encode(ciphertext)
print("This is encoded --> "..encoded)
print(#encoded)
local decoded = base64.decode(encoded)
print("This is decoded --> "..decoded)
