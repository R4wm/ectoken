local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat
local aes = require "resty.nettle.aes"
local base64 = require "resty.nettle.base64"
local os = require "os"

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

-- ---------
-- create_iv
-- ---------
function create_iv()
   local random = require "resty.random"
   local bytes = random.bytes(8)
   -- hash it for consistent length
   return base64.encode(bytes)
end

--------------
-- convert_key
--------------
function convert_key(a_key)
        local hmac = require "resty.nettle.hmac"
        local hash = hmac.sha256.new(a_key)
        hash = hmac.md5.new(a_key)

        hash:update(a_key)
        local dgst = hash:digest()

        return hex(dgst)
end
------------
--encrypt_v3
------------
function encrypt_v3(a_key, a_token)
   --  aes.new(key, mode, iv, ad)
   l_key = convert_key(a_key)
   l_iv = create_iv()
   l_ad = string.random(16)

   local aes256, err = aes.new(l_key, "gcm", l_iv, l_ad)
   
   -- check for error
   if aes256 == nil then
      print("aes256 is nil..")
      print(err)
   end

   -- encrypt
   local ciphertext, digest = aes256:encrypt(a_token)
   ciphertext = base64.encode(ciphertext, true)
   
   --VERBOSE INFO
   if VERBOSE then
      print("l_key: "..l_key)
      print("l_iv: "..l_iv)
      print("l_ad: "..l_ad)
      print("digest: "..digest)
      print("ciphertext: "..ciphertext)
      print("ciphertext len: "..#ciphertext)
   end
   
   return l_iv..l_ad..ciphertext
   -- return l_iv

end

-- -------
-- decrypt
-- -------
function decrypt_v3(a_key, a_token)
   -- parse token
   local iv = string.sub(a_token, 0, 12)
   local ad = string.sub(a_token, 13, 28)
   local cipher = string.sub(a_token, 29)
   -- decode base64 cipher
   cipher = base64.decode(cipher, true)
   local key = convert_key(a_key)
   -- decrypt
   local aes256 = aes.new(key, "gcm", iv, ad)
   local plaintext, digest = aes256:decrypt(cipher)

   -- VERBOSE INFO
   if VERBOSE then   
      print("key: "..key)
      print("l_iv: "..iv)
      print("l_ad: "..ad)
      print("digest: "..digest)
      print("l_ciper: "..cipher)
      print("plaintext: "..plaintext)
   end
   
   return plaintext   
end


local e = {}

function test()
   return "ectoken module OK"
end

e.test = test
e.encrypt = encrypt_v3
e.decrypt = decrypt_v3
e.create_iv = create_iv
return e
-- END TEST--

-- -- --------
-- -- GLOBALS
-- -- --------
-- G_ALPHANUMERIC = '-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxzy'
-- G_RAND_SENTINEL_MIN_LEN = 4
-- G_RAND_SENTINEL_MAX_LEN = 8
-- G_IV_SIZE_BYTES = 12
-- G_AES_GCM_TAG_SIZE_BYTES = 16
-- VERBOSE = false

-- -- -----
-- -- usage
-- -- -----
-- local function print_usage()
--    usage_str = [[
-- optional:
--     -v   verbose
--     -d   decrypt
-- required:
--     -t   token
--     -k   key
-- ex: 
--     .ectoken.lua -t mytoken -k mysecretkey
--     .ectoken.lua -t MyH4$h5 -k mysecretkey -d -v
-- ]]
--    print(usage_str)
-- end




-- -- ----
-- -- main
-- -- ----
-- -- getopt alternative function taken from public domain at http://lua-users.org/wiki/AlternativeGetOpt
-- function getopt( arg, options )
--   local tab = {}
--   for k, v in ipairs(arg) do
--     if string.sub( v, 1, 2) == "--" then
--       local x = string.find( v, "=", 1, true )
--       if x then tab[ string.sub( v, 3, x-1 ) ] = string.sub( v, x+1 )
--       else      tab[ string.sub( v, 3 ) ] = true
--       end
--     elseif string.sub( v, 1, 1 ) == "-" then
--       local y = 2
--       local l = string.len(v)
--       local jopt
--       while ( y <= l ) do
--         jopt = string.sub( v, y, y )
--         if string.find( options, jopt, 1, true ) then
--           if y < l then
--             tab[ jopt ] = string.sub( v, y+1 )
--             y = l
--           else
--             tab[ jopt ] = arg[ k + 1 ]
--           end
--         else
--           tab[ jopt ] = true
--         end
--         y = y + 1
--       end
--     end
--   end
--   return tab
-- end

-- -- ----
-- -- main
-- -- ----
-- opts = getopt( arg, "kt" )
-- if opts.h then
--    print_usage()
--    os.exit(0)
-- elseif not opts.k then
--    print("key is required")
--    print_usage()
--    os.exit(1)
-- elseif not opts.t then
--    print("token is required")
--    print_usage()
--    os.exit(1)
-- elseif opts.v then
--    VERBOSE = true
-- end

-- if opts.d then
--    decrypted_plaintext = decrypt_v3(opts.k, opts.t)
--    print(decrypted_plaintext)
-- else
--    encrypted_hash = encrypt_v3(opts.k, opts.t)
--    print(encrypted_hash)
-- end
