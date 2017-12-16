#!/usr/local/bin/luajit-2.0.5

local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat

-- --------
-- GLOBALS
-- --------
G_ALPHANUMERIC = '-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxzy'
G_RAND_SENTINEL_MIN_LEN = 4
G_RAND_SENTINEL_MAX_LEN = 8
G_IV_SIZE_BYTES = 12
G_AES_GCM_TAG_SIZE_BYTES = 16


local charset = {}

-- qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890
for i = 48,  57 do table.insert(charset, string.char(i)) end
for i = 65,  90 do table.insert(charset, string.char(i)) end
for i = 97, 122 do table.insert(charset, string.char(i)) end

function string.random(length)
  math.randomseed(os.time())

  if length > 0 then
    return string.random(length - 1) .. charset[math.random(1, #charset)]
  else
    return ""
  end
end

local function hex(str,spacer)
	return (gsub(str,"(.)", function (c)
		return format("%02X%s", byte(c), spacer or "")
	end))
end


local aes = require "resty.nettle.aes"


------------
--encrypt_v3
------------
function encrypt_v3(a_key, a_token)

	--[[
	 aes.new(key, mode, iv, ad)
	]]

	l_key = convert_key(a_key)
	-- -------
	-- encrypt
	-- -------
	print("Encypt..")
	print("This is a_key --> "..a_key)
	print(#a_key)
	-- local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
	-- local aes256, err = aes.new(a_key, "gcm", "771e9aed45a7", a_token)

	local aes256, err = aes.new(a_key, "gcm", "771e9aed45a7", a_token)

	if aes256 == nil then
		print("aes256 is nil..")
		print(err)
	end


	local ciphertext, digest = aes256:encrypt(a_token)
	print("aes256 gcm enc", #ciphertext, hex(ciphertext))
	print("aes256 gcm dgst", #digest, hex(digest))
	print("MORE ABOUT ciphertext: ")
	print(type(ciphertext))


	-- -------
	-- decrypt
	-- -------

	print("Decrypt..")
	-- local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
local aes256 = aes.new(a_key, "gcm", "771e9aed45a7", a_token)
	local plaintext, digest = aes256:decrypt(ciphertext)
	print("aes256 gcm dec", #plaintext, plaintext)
	print("aes256 gcm dgst", #digest, hex(digest))
	print()

end


-- -----
-- SEED
-- -----
function seed()
	local yarrow = require "resty.nettle.yarrow"
	local y = yarrow.new()
	print("y.sources " ,y.sources)
	print("y.seeded ", y.seeded)
	-- print("Doing --> y:seed('testtesttesttesttesttesttesttest')")
	-- y:seed("testtesttesttesttesttesttesttest")
	print("Doing --> y:seed(hex(y:random(G_IV_SIZE_BYTES)")

	y:seed("testtesttesttesttesttesttesttest")
	print("y.seeded --> ", y.seeded)

	print("\nCompare")
	print("testtesttesttesttesttesttesttest")
	print(type("testtesttesttest"))
	print(hex(y:random(16)))
	print(type(hex(y:random(16))))

	print(hex(y:random(G_IV_SIZE_BYTES)))
	print(hex(y:random(G_IV_SIZE_BYTES)))

	y:fast_reseed()

	print(hex(y:random(G_IV_SIZE_BYTES)))

	y:slow_reseed()
	print(hex(y:random(G_IV_SIZE_BYTES)))
end

--------------
-- convert_key
--------------
function convert_key(a_key)
	local hmac = require "resty.nettle.hmac"
	local hash = hmac.sha256.new(a_key)
	local hash = hmac.md5.new(a_key)

	hash:update(a_key)
	local dgst = hash:digest()
	print("hmac sha256", #dgst, hex(dgst))
	print("hmac sha256 (no hex)", dgst)

	return hex(dgst)
end

-- ----
-- main
-- ----
-- Make key always 16 24 or 32


local hashed_key = convert_key("mykey")
local hashed_token = convert_key("mytoken")
encrypt_v3(hashed_key, hashed_token)
-- seed()
