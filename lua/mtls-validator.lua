--[[
SVLJmTLSValidatorLUA – Strict mTLS Certificate Validator for Apache HTTP Server

File: mtls-validator.lua
Version: 1.4.5
Author: Odd-Arne Haraldsen

Description:
    This file implements strict mTLS validation for Apache HTTP Server using mod_lua.
    It enforces Zero Trust authentication based on a client TLS certificate and applies:
      - Ensures the connection is HTTPS and a client certificate is present (mandatory)
      - Certificate chain validation (mandatory)
      - CRL revocation check via CDP (mandatory)
      - Validity period check (mandatory, with distinct reason codes)
      - Issuer CN match against CA bundle (mandatory)
      - Optional issuer thumbprint validation
      - Optional client certificate thumbprint
      - Optional signature algorithm validation
      - Optional serial number whitelist
      - Optional EKU OID validation
      - Optional IP bypass (internal whitelist)

Apache Integration:
    Requires mod_ssl and mod_lua

    Example config:
        SSLVerifyClient require
        LuaHookFixups /etc/apache2/mtls/mtls-validator.lua validate_mtls

Dependencies:
    - lua-openssl
    - mtls-config.lua
    - mtls-config.properties
--]]

local openssl = require "openssl"
local x509 = openssl.x509
local digest = openssl.digest
local config = require "mtls-config"
local conf = config.load("/etc/apache2/mtls/mtls-config.properties")

-- Optional IP bypass (internal requests)
local function is_bypass_ip(ip)
    for entry, _ in pairs(conf.internal_bypass_ips or {}) do
        if ip == entry then return true end
    end
    return false
end

-- Redirect to error page with reason code
local function redirect(reason)
    r.headers_out["Location"] = (conf.error_redirect_url or "/error/403c.html") .. "?reason=" .. reason
    return apache2.HTTP_MOVED_TEMPORARILY
end

-- Validate certificate chain against CA bundle
local function validate_chain(cert, ca_bundle_path)
    local store = openssl.x509.store:new()
    local f = io.open(ca_bundle_path, "r")
    if not f then return false, "issuer-not-trusted" end
    local pem = f:read("*a"); f:close()

    for entry in pem:gmatch("-----BEGIN.-?CERTIFICATE.-?-----.-?END.-?CERTIFICATE.-?-----") do
        local ca = x509.read(entry)
        if ca then store:add(ca) end
    end

    local ok, err = store:verify(cert)
    if not ok then return false, "issuer-not-trusted" end
    return true
end

-- Check if cert is revoked using CRL (CDP HTTP/HTTPS only)
local function check_crl(cert)
    local crl_urls = {}
    for _, ext in ipairs(cert:extensions()) do
        if ext:object():sn() == "crlDistributionPoints" then
            for url in tostring(ext):gmatch("http[s]?://[%w%p]+") do
                table.insert(crl_urls, url)
            end
        end
    end
    if #crl_urls == 0 then return false, "crl-check-failed" end

    local serial = cert:serial():tostring()
    for _, url in ipairs(crl_urls) do
        local f = io.popen("curl -s '" .. url .. "'")
        local crl_pem = f:read("*a")
        f:close()

        if crl_pem and crl_pem:match("BEGIN X509 CRL") then
            local crl = openssl.x509.crl.read(crl_pem)
            if crl and crl:is_revoked(serial) then
                return false, "crl-check-failed"
            end
        else
            return false, "crl-check-failed"
        end
    end
    return true
end

-- Main Apache hook
function validate_mtls(r)
    if r.uri:match("^" .. (conf.error_redirect_url or "/403c.html")) then
        return apache2.DECLINED
    end

    local client_ip = r.useragent_ip or r.connection.remote_ip
    if conf.internal_bypass_ips and is_bypass_ip(client_ip) then
        return apache2.DECLINED
    end

    local ssl_protocol = r.subprocess_env["SSL_PROTOCOL"]
    if not ssl_protocol or ssl_protocol == "" then
        return redirect("insecure-connection")
    end

    local pem = r.subprocess_env["SSL_CLIENT_CERT"]
    if not pem then return redirect("cert-missing") end

    local cert = x509.read(pem)
    if not cert then return redirect("cert-missing") end

    local now = os.time()
    if cert:notbefore() > now then
        return redirect("cert-notyetvalid")
    elseif cert:notafter() < now then
        return redirect("cert-expired")
    end

    if conf.allowed_signature_algorithms then
        local sigalg = cert:sig_alg()
        if not conf.allowed_signature_algorithms[sigalg] then
            return redirect("sigalg-not-allowed")
        end
    end

    -- Match issuer CN + optional thumbprint
    local found = false
    local bundle = io.open(conf.ca_bundle_path, "r")
    if not bundle then return redirect("issuer-not-trusted") end
    local pem = bundle:read("*a"); bundle:close()

    for entry in pem:gmatch("-----BEGIN.-?CERTIFICATE.-?-----.-?END.-?CERTIFICATE.-?-----") do
        local ca = x509.read(entry)
        if ca and ca:subject():oneline() == cert:issuer():oneline() then
            if conf.issuer_thumbprint then
                local fp = digest.new("sha1"):final(ca:export("DER")):gsub(".", function(c)
                    return string.format("%02X", c:byte())
                end)
                if fp == conf.issuer_thumbprint then
                    found = true
                    break
                end
            else
                found = true
                break
            end
        end
    end
    if not found then return redirect("issuer-not-trusted") end

    local ok, reason = validate_chain(cert, conf.ca_bundle_path)
    if not ok then return redirect(reason) end

    local ok, reason = check_crl(cert)
    if not ok then return redirect(reason) end

    if conf.allowed_client_thumbprints then
        local client_fp = digest.new("sha1"):final(cert:export("DER")):gsub(".", function(c)
            return string.format("%02X", c:byte())
        end)
        if not conf.allowed_client_thumbprints[client_fp] then
            return redirect("client-thumbprint-not-allowed")
        end
    end

    if conf.cert_serial_numbers then
        local serial = cert:serial():tostring()
        if not conf.cert_serial_numbers[serial] then
            return redirect("serial-not-allowed")
        end
    end

    if conf.allowed_eku_oids then
        local eku_valid = false
        for _, e in ipairs(cert:extensions()) do
            if e:object():sn() == "extendedKeyUsage" then
                for oid in tostring(e):gmatch("[0-9%.]+") do
                    if conf.allowed_eku_oids[oid] then
                        eku_valid = true
                        break
                    end
                end
            end
        end
        if not eku_valid then
            return redirect("eku-not-allowed")
        end
    end

    return apache2.DECLINED
end
