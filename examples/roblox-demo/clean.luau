-- DEMO ONLY — codigo Luau legitimo: cero hallazgos del pack
local Players = game:GetService("Players")

local function onPlayerAdded(player)
    local coins = Instance.new("IntValue")
    coins.Name = "Coins"
    coins.Value = 0
    coins.Parent = player
end

Players.PlayerAdded:Connect(onPlayerAdded)
