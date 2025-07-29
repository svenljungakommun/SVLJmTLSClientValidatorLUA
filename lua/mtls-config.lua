--[[
SVLJmTLSValidatorLUA – Configuration Parser

File: mtls-config.lua
Version: 1.4.5
Author: Odd-Arne Haraldsen

Description:
    Parses a .properties config file for strict mTLS validation.
    Supports:
    - Strings
    - Booleans ("true"/"false")
    - Comma-separated lookup tables (stored as Lua tables with true-values)

Returned keys:
    - issuer_name : string (used as issuer_cn)
    - issuer_thumbprint : string
    - cert_serial_numbers : table
    - allowed_client_thumbprints : table
    - allowed_eku_oids : table
    - allowed_signature_algorithms : table
    - ca_bundle_path : string
    - error_redirect_url : string
    - internal_bypass_ips : table
--]]

local config = {}

function config.load(path)
    local cfg = {}
    for line in io.lines(path) do
        local key, value = line:match("^%s*([^#;][^=]*)=(.*)$")
        if key and value then
            key = key:match("^%s*(.-)%s*$"):lower()
            value = value:match("^%s*(.-)%s*$")
            if key:match("thumbprints") or key:match("oids") or key:match("algorithms")
               or key:match("serial_numbers") or key:match("bypass_ips") then
                local list = {}
                for item in value:gmatch("[^,]+") do
                    list[item:upper():gsub("%s+", "")] = true
                end
                cfg[key] = list
            elseif value:lower() == "true" then
                cfg[key] = true
            elseif value:lower() == "false" then
                cfg[key] = false
            else
                cfg[key] = value
            end
        end
    end
    return cfg
end

return config
