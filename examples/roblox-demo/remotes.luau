-- DEMO ONLY — confianza cliente-servidor y economia sin validacion
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local MarketplaceService = game:GetService("MarketplaceService")
local DataStoreService = game:GetService("DataStoreService")

local remote = ReplicatedStorage:FindFirstChild("GiveCoins")

remote.OnServerEvent:Connect(function(player, amount)
    player.leaderstats.Coins.Value += amount
end)

remote.OnServerInvoke = function(player, itemId)
    return itemId
end

MarketplaceService.ProcessReceipt = function(receiptInfo)
    return Enum.PurchaseDecision.PurchaseGranted
end

DataStoreService:GetDataStore("PlayerData"):SetAsync("p1", { coins = 999 })
