#!/usr/local/bin/luajit-2.0.5

local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat
local aes = require "resty.nettle.aes"
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

-- -------------
-- string.random
-- -------------
function string.random(length)
  math.randomseed(os.time())

  if length > 0 then
    return string.random(length - 1) .. charset[math.random(1, #charset)]
  else
    return ""
  end
end
-- ---
-- hex
-- ---
local function hex(str,spacer)
        return (gsub(str,"(.)", function (c)
                return format("%02X%s", byte(c), spacer or "")
        end))
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
        print("From convert_key --> ")
        print("hmac sha256", #dgst, hex(dgst))
        print("hmac sha256 (no hex)", dgst)
        print("End convert_key..")
        return hex(dgst)
end
-- -------
-- decrypt
-- -------
function decrypt_v3(a_key, a_token)
   -- -------
   -- decrypt
   -- -------
   print("Decrypt..")
   l_iv = string.sub(a_token, 0, 12)
   l_cipher = string.sub(a_token, 13, 30)
   l_ad = string.sub(a_token, 31)
   l_key = convert_key(a_key)
   print("This is iv --> "..l_iv)
   print("This is l_cipher --> "..l_cipher)
   print("This is l_ad --> "..l_ad)
   print("This is l_key ", l_key)
   print("This is a_token passed in --> "..a_token)
--    print("This is a_key --> "..a_key)
--    l_key = convert_key(a_key)
--    print("This is l_key --> "..l_key)
   local aes256 = aes.new(l_key, "gcm", l_iv, l_ad)
-- local aes256 = aes.new(l_key, "gcm", "771e9aed45a7", a_token)
   local plaintext, digest = aes256:decrypt(hex(l_cipher))
   print("aes256 gcm dec", #plaintext, plaintext)
   print("aes256 gcm dec", #plaintext, hex(plaintext))
   print("aes256 gcm dgst", #digest, hex(digest))
   print()
end
-- ---------
-- create_iv
-- ---------
function create_iv()
   local random = require "resty.random"
   local bytes = random.bytes(12)
   print(bytes)
end
------------
--encrypt_v3
------------
function encrypt_v3(a_key, a_token)
   --  aes.new(key, mode, iv, ad)
   l_key = convert_key(a_key)
   l_iv = "771e9aed45a7" --static for now until random.lua is working
   l_ad = string.random(G_AES_GCM_TAG_SIZE_BYTES)
   print("THis is l_ad --> "..l_ad)

   print("\nEncypt..")
   print("This is l_key --> "..l_key)
   print("This is l_iv --> "..l_iv)
   print(#l_key)

   local aes256, err = aes.new(l_key, "gcm", l_iv, l_ad)

   if aes256 == nil then
      print("aes256 is nil..")
      print(err)
   end
   print("Now encrypting --> ", a_token)
   local ciphertext, digest = aes256:encrypt(a_token)
   print("aes256 gcm enc", #ciphertext, hex(ciphertext))
   print("aes256 gcm dgst", #digest, hex(digest))

   print("type l_iv --> "..type(l_iv))
   print("type hex(ciphertext) --> "..type(hex(ciphertext)))
   return l_iv..hex(ciphertext)..l_ad
   -- return l_iv..ciphertext..l_ad
end
-- ----
-- main
-- ----
local ciphertext = encrypt_v3("somekey", "sometoken")
print("From main, this is ciphertext --> "..ciphertext)
decrypt_v3("somekey", ciphertext)
