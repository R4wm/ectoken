#!/usr/local/bin/luajit-2.0.5
local random = require "resty.random"
-- Get two random bytes
local bytes = random.bytes(2)
-- Get two random bytes hexadecimal encoded
