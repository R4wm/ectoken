#!/usr/local/bin/luajit-2.0.5

local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat
local aes = require "resty.nettle.aes"
local base64 = require "resty.nettle.base64"
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
--------------
-- convert_key
--------------
function convert_key(a_key)
        local hmac = require "resty.nettle.hmac"
        local hash = hmac.sha256.new(a_key)
        local hash = hmac.md5.new(a_key)

        hash:update(a_key)
        local dgst = hash:digest()

        return hex(dgst)
end
-- -------
-- decrypt
-- -------
function decrypt_v3(a_key, a_token)
   l_iv = string.sub(a_token, 0, 12)
   l_cipher = string.sub(a_token, 13, 24)
   l_cipher = base64.decode(l_cipher)
   l_ad = string.sub(a_token, 25)
   l_key = convert_key(a_key)
   -- decrypt
   local aes256 = aes.new(l_key, "gcm", l_iv, l_ad)
   local plaintext, digest = aes256:decrypt(l_cipher)
   
   return plaintext
end
-- ---------
-- create_iv
-- ---------
function create_iv()
   local random = require "resty.random"
   local bytes = random.bytes(12)
end
------------
--encrypt_v3
------------
function encrypt_v3(a_key, a_token)
   --  aes.new(key, mode, iv, ad)
   l_key = convert_key(a_key)
   l_iv = "771e9aed45a7" --static for now until random.lua is working
   l_ad = string.random(G_AES_GCM_TAG_SIZE_BYTES)

   local aes256, err = aes.new(l_key, "gcm", l_iv, l_ad)
   -- check for error
   if aes256 == nil then
      print("aes256 is nil..")
      print(err)
   end
   -- encrypt
   local ciphertext, digest = aes256:encrypt(a_token)
   ciphertext = base64.encode(ciphertext)

   return l_iv..ciphertext..l_ad
end
-- ----
-- main
-- ----
local ciphertext = encrypt_v3("somekey", "thisissomekindacrazytokenyouknow?")
print("From main, this is ciphertext --> "..ciphertext)
local decrypted = decrypt_v3("somekey", ciphertext)
print("From main, this is decrypted ciphertext --> "..decrypted)
