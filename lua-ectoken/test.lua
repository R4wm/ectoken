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


local function hex(str,spacer)
	return (gsub(str,"(.)", function (c)
		return format("%02X%s", byte(c), spacer or "")
	end))
end

------------
-- MD2 stuff
------------
function do_md2()
	do
		local md2 = require "resty.nettle.md2"
		print("md2      ", #md2(""), hex(md2("")))
		local hash = md2.new()
		hash:update("")
		print("md2     ", #hash:digest(), hex(hash:digest()))
	end
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
	-- local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
	-- local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
	local aes256 = aes.new(a_key, "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
	local ciphertext, digest = aes256:encrypt(a_token)
	print("aes256 gcm enc", #ciphertext, hex(ciphertext))
	print("aes256 gcm dgst", #digest, hex(digest))




	--[[
	-- -------
	-- decrypt
	-- -------

	print("Decrypt..")
	local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
	local plaintext, digest = aes256:decrypt(ciphertext)
	print("aes256 gcm dec", #plaintext, plaintext)
	print("aes256 gcm dgst", #digest, hex(digest))
	print()
	]]
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
convert_key("somekey")


-- encrypt_v3("somekey", "sometoken")
-- seed()
