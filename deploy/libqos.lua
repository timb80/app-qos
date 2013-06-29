------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
-- External Bandwidth QoS Manager.
-- See /etc/clearos/qos.conf for configuration settings.
--
------------------------------------------------------------------------------
--
-- Copyright (C) 2012-2013 ClearFoundation
-- 
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

------------------------------------------------------------------------------
--
-- F U N C T I O N S
--
------------------------------------------------------------------------------

function PackCustomRule(s)
    local c = 1

    while c > 0 do
        s, c = string.gsub(s, "  ", " ")
    end

    c = 1
    while c > 0 do
        s, c = string.gsub(s, "\t", "")
    end

    c = 1
    while c > 0 do
        s, c = string.gsub(s, "\n\n", "\n")
    end

    c = 1
    while c > 0 do
        s, c = string.gsub(s, "\n ", "\n")
    end

    if string.sub(s, 1, 1) == " " then
        s = string.sub(s, 2)
    end

    if string.sub(s, string.len(s)) == " " then
        s = string.sub(s, 1, string.len(s) - 1)
    end

    return s .. "\n"
end

function ParseInterfaceValue(v)
    local t = {}
    local entries = {}
    local cfg
    local ifn
    local rate
    local r2q

    if v == nil or string.len(v) == 0 then return t end

    entries = Explode(" ", string.gsub(PackWhitespace(v), "\t", ""))

    for _, cfg in pairs(entries) do
        if cfg ~= nil and string.len(cfg) ~= 0 then
            __, __, ifn, rate, r2q = string.find(cfg, "(%w+):(%d+):(%w+)")

            if ifn == nil or rate == nil or r2q == nil then
                error("Invalid interface configuration syntax detected: " .. cfg)
            end

            t[ifn] = {}
            t[ifn]["rate"] = rate
            t[ifn]["r2q"] = r2q
        end
    end

    return t
end

function ParseBandwidthValue(v, buckets)
    local i
    local t = buckets
    local entries = {}
    local cfg
    local ifn
    local value = {}

    if v == nil or string.len(v) == 0 then return t end

    entries = Explode(" ", string.gsub(PackWhitespace(v), "\t", ""))

    for _, cfg in pairs(entries) do
        if cfg ~= nil and string.len(cfg) ~= 0 then
            __, __, ifn, value[0], value[1], value[2],
            value[3], value[4], value[5], value[6] = string.find(
                cfg, "(%w+):(%d+):(%d+):(%d+):(%d+):(%d+):(%d+):(%d+)"
            )

            if ifn == nil or value == nil then
                echo("Invalid bandwidth value syntax detected: " .. cfg)
                return nil
            end

            for i = 0, 6 do
                value[i] = tonumber(value[i])
            end
            t[ifn] = value
        end
    end

    return t
end

function InitializeBandwidthReserved(rate_ifn)
    local i
    local ifn
    local limit
    local rate_res = {}

    for ifn, _ in pairs(rate_ifn) do
        rate_res[ifn] = {}
        for i = 0, 6 do
            rate_res[ifn][i] = tonumber(0)
        end
        limit = 100
        while limit > 0 do
            for i = 0, 6 do
                rate_res[ifn][i] = rate_res[ifn][i] + 1
                limit = limit - 1
                if limit == 0 then break end
            end
        end
    end

    return rate_res
end

function InitializeBandwidthLimit(rate_ifn)
    local i
    local ifn
    local rate_limit = {}

    for ifn, _ in pairs(rate_ifn) do
        rate_limit[ifn] = {}
        for i = 0, 6 do
            rate_limit[ifn][i] = 100
        end
    end

    return rate_limit
end

function ValidateBandwidthReserved(name, rate_res)
    local i
    local r
    local ifn
    local rate
    local limit

    for ifn, r in pairs(rate_res) do
        limit = 100
        for _, rate in pairs(r) do
            limit = limit - rate
            if limit < 0 then
                error(name .. " bandwidth overflow (>100%) for interface: " .. ifn)
            end
        end
        if limit > 0 then
            debug(string.format("%s bandwidth underflow, %d%%%% unassigned for interface: %s", name, limit, ifn))
        end
        while limit > 0 do
            for i = 0, 6 do
                rate_res[ifn][i] = rate_res[ifn][i] + 1
                limit = limit - 1
                debug(string.format("%s: adding 1%%%% to bucket #%d for interface: %s", name, i, ifn))
                if limit == 0 then break end
            end
        end
    end
end

function ValidateBandwidthLimit(name, rate_res, rate_limit)
    local i
    local r
    local ifn
    local limit

    for ifn, r in pairs(rate_limit) do
        for i, limit in pairs(r) do
            if limit < rate_res[ifn][i] then
                error(string.format("%s bandwidth underflow (<%d%%, bucket #%d) for interface: %s", name, rate_res[ifn][i], i, ifn))
            end
            if limit > 100 then
                error(string.format("%s bandwidth overflow (>%d%%, bucket #%d) for interface: %s", name, 100, i, ifn))
            end
        end
    end
end

function CalculateRateToQuantum(rate)
    local r2q = 1
    local quantum = 20000

    while quantum > 1500 do
        quantum = (rate * 1000 / 8) / r2q
        r2q = r2q + 1
    end

    r2q = r2q - 2
    quantum = (rate * 1000 / 8) / r2q
    debug("Auto-r2q for rate " .. rate ..
        ": " .. r2q .. " (quantum: " .. quantum .. ")")

    return r2q
end

function QosExecute(direction, rate_ifn, rate_res, rate_limit, priomark)
    local id = 0
    local rule
    local rate
    local limit
    local param
    local ifn_name
    local ifn_conf
    local chain_qos

    if direction == 1 then
        execute(string.format("%s %s numdevs=%d",
            MODPROBE, "imq",
            TableCount(WANIF_CONFIG)))
    end

    for _, ifn in pairs(WANIF_CONFIG) do
        if direction == 0 then
            ifn_name = ifn
            chain_qos = "BWQOS_UP_" .. ifn
            execute(IPBIN .. " link set dev " .. ifn .. " qlen 30")
        else
            ifn_name = "imq" .. id
            chain_qos = "BWQOS_DOWN_" .. ifn
            execute(IPBIN .. " link set " .. ifn_name .. " up")
        end

        execute(TCBIN .. " qdisc add dev " .. ifn_name ..
            " root handle 1: htb default " .. (id + 1) .. "6" ..
            " r2q " .. rate_ifn[ifn]["r2q"])
        execute(TCBIN .. " class add dev " .. ifn_name ..
            " parent 1: classid 1:1 htb rate " ..
            rate_ifn[ifn]["rate"] .. "kbit")

        for i = 0, 6 do
            rate = rate_res[ifn][i] * rate_ifn[ifn]["rate"] / 100
            limit = rate_limit[ifn][i] * rate_ifn[ifn]["rate"] / 100

            execute(TCBIN .. " class add dev " .. ifn_name ..
                " parent 1:1 classid 1:" ..
                (id + 1) .. i .. " htb rate " ..
                rate .. "kbit ceil " .. limit .. "kbit prio " .. i)
            execute(TCBIN .. " qdisc add dev " .. ifn_name ..
                " parent 1:" .. (id + 1) .. i ..
                " handle " .. (id + 1) .. i ..
                ": sfq perturb 10")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 prio 0 protocol ip handle " ..
                (id + 1) .. i ..
                " fw flowid 1:" .. (id + 1) .. i)
        end

        -- Create QoS chain
        iptc_create_chain("mangle", chain_qos)

        -- Add configured MARK rules
        for _, rule in ipairs(priomark.ipv4) do
            if tonumber(rule.enabled) and (rule.ifn == ifn or rule.ifn == '*') then
                param = " "
                if tonumber(rule.type) == direction then
                    if rule.proto ~= "-" then
                        if string.sub(rule.proto, 1, 1) == "!" then
                            param = param .. "! -p " ..
                                string.sub(rule.proto, 2) .. " "
                        else
                            param = param .. "-p " .. rule.proto .. " "
                        end
                    end
                    if rule.saddr ~= "-" then
                        param = param .. "-s" .. rule.saddr .. " "
                    end
                    if rule.sport ~= "-" then
                        param = param .. "--sport " .. rule.sport .. " "
                    end
                    if rule.daddr ~= "-" then
                        param = param .. "-d " .. rule.daddr .. " "
                    end
                    if rule.dport ~= "-" then
                        param = param .. "--dport " .. rule.dport .. " "
                    end

                    iptables("mangle", "-A " .. chain_qos .. param ..
                        "-j MARK --set-mark " .. (id + 1) .. rule.prio)
                end
            end
        end

        for _, rule in ipairs(priomark.ipv4_custom) do
            if tonumber(rule.enabled) and (rule.ifn == ifn or rule.ifn == '*') then
                param = " "
                if tonumber(rule.type) == direction then
                    iptables("mangle", "-A " .. chain_qos .. 
                        " " .. rule.param ..
                        " -j MARK --set-mark " .. (id + 1) .. rule.prio)
                end
            end
        end

        if direction == 0 then
            iptables("mangle",
                "-I POSTROUTING -o " .. ifn .. " -j " .. chain_qos)
        else
            iptables("mangle",
                "-A " .. chain_qos .. " -j IMQ --todev " .. id)
            iptables("mangle",
                "-I PREROUTING -i " .. ifn .. " -j " .. chain_qos)
        end

        id = id + 1
    end
end

------------------------------------------------------------------------------
--
-- RunBandwidthExternal
--
-- Initialize QoS classes, add custom priority rules.
--
------------------------------------------------------------------------------

function RunBandwidthExternal()
    local ifn
    local r2q
    local rate
    local rate_up = {}
    local rate_up_res = {}
    local rate_up_limit = {}
    local rate_down = {}
    local rate_down_res = {}
    local rate_down_limit = {}
    local rule
    local rules
    local priomark = { ipv4={}, ipv6={}, custom={} }

    echo("Running external QoS bandwidth manager")

    if QOS_PRIOMARK4 ~= nil then
        rules = Explode(" ",
            string.gsub(PackWhitespace(QOS_PRIOMARK4), "\t", ""))
        for _, rule in pairs(rules) do
            if rule ~= nil and string.len(rule) ~= 0 then
                rule = Explode("|", rule)
                table.insert(priomark.ipv4, {
                    name=rule[1], ifn=rule[2],
                    enabled=rule[3], type=rule[4],
                    prio=rule[5], proto=rule[6],
                    saddr=rule[7], sport=rule[8],
                    daddr=rule[9], dport=rule[10]
                })
            end
        end
    end

    if QOS_PRIOMARK6 ~= nil then
        rules = Explode(" ",
            string.gsub(PackWhitespace(QOS_PRIOMARK6), "\t", ""))
        for _, rule in pairs(rules) do
            if rule ~= nil and string.len(rule) ~= 0 then
                rule = Explode("|", rule)
                table.insert(priomark.ipv6, {
                    name=rule[1], ifn=rule[2],
                    enabled=rule[3], type=rule[4],
                    prio=rule[5], proto=rule[6],
                    saddr=rule[7], sport=rule[8],
                    daddr=rule[9], dport=rule[10]
                })
            end
        end
    end

    if QOS_PRIOMARK4_CUSTOM ~= nil then
        rules = Explode("\n", PackCustomRule(QOS_PRIOMARK4_CUSTOM))
        for _, rule in pairs(rules) do
            if rule ~= nil and string.len(rule) ~= 0 then
                rule = Explode("|", rule)
                table.insert(priomark.ipv4_custom, {
                    name=rule[1], ifn=rule[2],
                    enabled=rule[3], type=rule[4],
                    prio=rule[3], param=rule[4]
                })
            end
        end
    end

    if QOS_PRIOMARK6_CUSTOM ~= nil then
        rules = Explode("\n", PackCustomRule(QOS_PRIOMARK6_CUSTOM))
        for _, rule in pairs(rules) do
            if rule ~= nil and string.len(rule) ~= 0 then
                rule = Explode("|", rule)
                table.insert(priomark.ipv6_custom, {
                    name=rule[1], ifn=rule[2],
                    enabled=rule[3], type=rule[4],
                    prio=rule[3], param=rule[4]
                })
            end
        end
    end

    for _, ifn in pairs(WANIF_CONFIG) do
        execute(TCBIN .. " qdisc del dev " .. ifn .. " root >/dev/null 2>&1")
    end

    rate_up = ParseInterfaceValue(QOS_UPSTREAM)
    rate_down = ParseInterfaceValue(QOS_DOWNSTREAM)

    rate_up_res = InitializeBandwidthReserved(rate_up)
    rate_up_limit = InitializeBandwidthLimit(rate_up)
    rate_down_res = InitializeBandwidthReserved(rate_down)
    rate_down_limit = InitializeBandwidthLimit(rate_down)

    rate_up_res = ParseBandwidthValue(QOS_UPSTREAM_BWRES, rate_up_res)
    rate_up_limit = ParseBandwidthValue(QOS_UPSTREAM_BWLIMIT, rate_up_limit)
    rate_down_res = ParseBandwidthValue(QOS_DOWNSTREAM_BWRES, rate_down_res)
    rate_down_limit = ParseBandwidthValue(QOS_DOWNSTREAM_BWLIMIT, rate_down_limit)
    
    validateBandwidthReserved("Reserved upstream", rate_up_res)
    validateBandwidthReserved("Reserved downstream", rate_down_res)
    validateBandwidthLimit("Upstream limit", rate_up_res, rate_up_limit)
    validateBandwidthLimit("Downstream limit", rate_down_res, rate_down_limit)

    for _, ifn in pairs(WANIF_CONFIG) do
        rate_up[ifn]["min_rate"] = rate_up[ifn]["rate"]
        rate_down[ifn]["min_rate"] = rate_down[ifn]["rate"]

        for i, rate in pairs(rate_up_res[ifn]) do
            rate = rate * rate_up[ifn]["rate"] / 100
            if rate < tonumber(rate_up[ifn]["min_rate"]) then
                rate_up[ifn]["min_rate"] = rate
            end
        end
        for i, rate in pairs(rate_down_res[ifn]) do
            rate = rate * rate_down[ifn]["rate"] / 100
            if rate < tonumber(rate_down[ifn]["min_rate"]) then
                rate_down[ifn]["min_rate"] = rate
            end
        end
    end

    for _, ifn in pairs(WANIF_CONFIG) do
        if rate_up[ifn]["r2q"] == "auto" then
            rate_up[ifn]["r2q"] = CalculateRateToQuantum(rate_up[ifn]["min_rate"])
        end
        if rate_down[ifn]["r2q"] == "auto" then
            rate_down[ifn]["r2q"] = CalculateRateToQuantum(rate_down[ifn]["min_rate"])
        end
    end

    qosExecute(0, rate_up, rate_up_res, rate_up_limit, priomark)
    qosExecute(1, rate_down, rate_down_res, rate_down_limit, priomark)
end

-- vi: syntax=lua expandtab shiftwidth=4 softtabstop=4 tabstop=4
