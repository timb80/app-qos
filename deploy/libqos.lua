------------------------------------------------------------------------------
--
-- ClearOS Firewall
--
-- External Bandwidth QoS Manager, with support for Differentiated Services (DSCP)
-- See /etc/clearos/qos.conf for configuration settings.
--
------------------------------------------------------------------------------
--
-- Copyright (C) 2012-2013 ClearFoundation
-- Copyright (C) 2013 Tim Burgess
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
-- G L O B A L S
--
------------------------------------------------------------------------------

QOS_WANIF = {}

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
            debug("Parse interface config " .. cfg)
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
            value[3], value[4], value[5] = string.find(
                cfg, "([%w*]+):(%d+):(%d+):(%d+):(%d+):(%d+):(%d+)"
            )
            debug("Parse bandwidth config " .. v .. " .. " .. cfg)
            if ifn == nil or value == nil then
                echo("Invalid bandwidth value syntax detected: " .. cfg)
                return nil
            end

            for i = 0, 5 do
                value[i] = tonumber(value[i])
            end
            t[ifn] = value
        end
    end

    return t
end

function InitializeBandwidthReserved(rate_ifn, rate_res)
    local i
    local ifn
    local limit

    for ifn, _ in pairs(rate_ifn) do
        if rate_res[ifn] == nil then
            if rate_res['*'] ~= nil then
                rate_res[ifn] = rate_res['*']
            else
                rate_res[ifn] = {}
                for i = 0, 5 do
                    rate_res[ifn][i] = tonumber(0)
                end
                limit = 100
                while limit > 0 do
                    for i = 0, 5 do
                        rate_res[ifn][i] = rate_res[ifn][i] + 1
                        limit = limit - 1
                        if limit == 0 then break end
                    end
                end
            end
        end
    end

    return rate_res
end

function InitializeBandwidthLimit(rate_ifn, rate_limit)
    local i
    local ifn

    for ifn, _ in pairs(rate_ifn) do
        if rate_limit[ifn] == nil then
            if rate_limit['*'] ~= nil then
                rate_limit[ifn] = rate_limit['*']
            else
                rate_limit[ifn] = {}
                for i = 0, 5 do
                    rate_limit[ifn][i] = 100
                end
            end
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
                echo(name .. " bandwidth overflow (>100%) for interface: " .. ifn)
                return false
            end
        end
        if limit > 0 then
            debug(string.format("%s bandwidth underflow, %d%%%% unassigned for interface: %s", name, limit, ifn))
        end
        while limit > 0 do
            for i = 0, 5 do
                rate_res[ifn][i] = rate_res[ifn][i] + 1
                limit = limit - 1
                debug(string.format("%s: adding 1%%%% to bucket #%d for interface: %s", name, i, ifn))
                if limit == 0 then break end
            end
        end
    end
    
    return true
end

function ValidateBandwidthLimit(name, rate_res, rate_limit)
    local i
    local r
    local ifn
    local limit

    for ifn, r in pairs(rate_limit) do
        for i, limit in pairs(r) do
            if limit < rate_res[ifn][i] then
                echo(string.format("%s bandwidth underflow (<%d%%, bucket #%d) for interface: %s", name, rate_res[ifn][i], i, ifn))
                return false
            end
            if limit > 100 then
                echo(string.format("%s bandwidth overflow (>%d%%, bucket #%d) for interface: %s", name, 100, i, ifn))
                return false
            end
        end
    end

    return true
end

function CalculateRateToQuantum(rate)
    local r2q = 1
    local quantum = 20000

    --total quantum needs to be above 10000 (bytes) to prevent kernel warnings
    while quantum > 1500 do
        quantum = (rate * 1000 / 8) / r2q
        r2q = r2q + 1
    end

    r2q = r2q - 2
    quantum = (rate * 1000 / 8) / r2q
    debug("Auto-r2q for minimum rate " .. rate ..
        ": " .. r2q .. " (quantum: " .. quantum .. ")")

    return r2q
end

function QosExecute(direction, rate_ifn, rate_res, rate_limit, priomark)
    local config
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
            TableCount(QOS_WANIF)))
    end

    for _, ifn in pairs(QOS_WANIF) do
        if direction == 0 then
            ifn_name = ifn
            chain_qos = "BWQOS_UP_" .. ifn
            execute(IPBIN .. " link set dev " .. ifn .. " qlen 30")
        else
            ifn_name = "imq" .. id
            chain_qos = "BWQOS_DOWN_" .. ifn
            execute(IPBIN .. " link set " .. ifn_name .. " up")
        end

        if direction == 0 then
            --dsmark and htb setup for egress (direction=0)
            execute(TCBIN .. " qdisc add dev " .. ifn_name ..
                " handle 1:0 root dsmark indices 64 set_tc_index")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                " parent 1:0 protocol ip prio 1 tcindex mask 0xfc shift 2 pass_on")
            execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                " parent 1:0 handle 2:0 htb r2q " .. rate_ifn[ifn]["r2q"])
            execute(TCBIN .. " class add dev " .. ifn_name  ..
                " parent 2:0 classid 2:1 htb rate " .. rate_ifn[ifn]["rate"] .. "kbit ceil " .. rate_ifn[ifn]["rate"] .. "kbit")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                " parent 2:0 protocol ip prio 1 tcindex mask 0xf0 shift 4 pass_on")

            for i=0,5 do
                rate = rate_res[ifn][i] * rate_ifn[ifn]["rate"] / 100
                rate = math.floor(rate)
                limit = rate_limit[ifn][i] * rate_ifn[ifn]["rate"] / 100

                if i == 5 then
                    --BE class 2:60 prio 6, red queue
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                    " parent 2:1 classid 2:60 htb rate " ..
                    rate .. "kbit ceil " .. limit .. "kbit prio " .. 6)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                    " parent 2:60 red limit 60KB min 15KB max 45KB burst 20 avpkt 1000 bandwidth "
                    .. rate .. "kbit probability 0.4")
                    execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 2:0 protocol ip prio 1 handle 0 tcindex classid 2:60")
                else 
                    if i == 0 then
                    --EF class 2:10 prio 1, pfifo short queue
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                        " parent 2:1 classid 2:10 htb rate " ..
                        rate .. "kbit ceil " .. limit .. "kbit prio " .. 1)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                        " parent 2:10 pfifo limit 5")
                    execute(TCBIN .. " filter add dev " .. ifn_name  ..
                        " parent 2:0 protocol ip prio 1 handle 5 tcindex classid 2:10")
                    else
                    --i=4,AF1 class 2:50 prio 5, gred queue, handle 1
                    --i=3,AF2 class 2:40 prio 4, gred queue, handle 2
                    --i=2,AF3 class 2:30 prio 3, gred queue, handle 3
                    --i=1,AF4 class 2:20 prio 2, gred queue, handle 4
                    prio = i+1
                    handle = 5-i
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                        " parent 2:1 classid 2:" .. prio .. "0 htb rate " ..
                        rate .. "kbit ceil " .. limit .. "kbit prio " .. prio)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                        " parent 2:" .. prio .. "0 gred setup DPs 4 default 2 grio")
                    execute(TCBIN .. " filter add dev " .. ifn_name  ..
                        " parent 2:0 protocol ip prio 1 handle " .. handle .. " tcindex classid 2:" .. prio .. "0")
                    --AF 3No. drop precendence sub classes
                    execute(TCBIN .. " qdisc change dev " .. ifn_name  ..
                        " parent 2:" .. prio .. "0 gred limit 60KB min 15KB max 45KB burst 20 avpkt 1000 bandwidth "
                        .. rate .. " DP 1 probability 0.02 prio 1")
                    execute(TCBIN .. " qdisc change dev " .. ifn_name  ..
                        " parent 2:" .. prio .. "0 gred limit 60KB min 15KB max 45KB burst 20 avpkt 1000 bandwidth "
                        .. rate .. " DP 2 probability 0.04 prio 2")
                    execute(TCBIN .. " qdisc change dev " .. ifn_name  ..
                        " parent 2:" .. prio .. "0 gred limit 60KB min 15KB max 45KB burst 20 avpkt 1000 bandwidth "
                        .. rate .. " DP 3 probability 0.06 prio 3")
                    end
                end
            end

            --DSMARK classifier elements, classid filter constructed 1:1yz
            --y = tcindex handle match (0,1,2,3,4,5)
            --z = sub class drop precedence match (0,1,2,3)
            --BE
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 0 tcindex classid 1:1")
            --CS1
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 8 tcindex classid 1:110")
            --AF1x
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 10 tcindex classid 1:111")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 12 tcindex classid 1:112")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 14 tcindex classid 1:113")
            --CS2
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 16 tcindex classid 1:120")
            --AF2x
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 18 tcindex classid 1:121")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 20 tcindex classid 1:122")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 22 tcindex classid 1:123")
            --CS3
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 24 tcindex classid 1:130")
            --AF3x
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 26 tcindex classid 1:131")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 28 tcindex classid 1:132")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 30 tcindex classid 1:133")
            --CS4
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 32 tcindex classid 1:140")
            --AF4x
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 34 tcindex classid 1:141")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 36 tcindex classid 1:142")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 38 tcindex classid 1:143")
            --CS5
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 40 tcindex classid 1:150")
            --EF
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 46 tcindex classid 1:151")
            --CS6, CS7 reserved but lumped into highest EF class
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 48 tcindex classid 1:150")
            execute(TCBIN .. " filter add dev " .. ifn_name  ..
                    " parent 1:0 protocol ip prio 1 handle 56 tcindex classid 1:150")
        else
            --htb setup for ingress (direction=1, default 1:60)
            execute(TCBIN .. " qdisc add dev " .. ifn_name ..
                " handle 1:0 root htb default 60 r2q " .. rate_ifn[ifn]["r2q"])
            execute(TCBIN .. " class add dev " .. ifn_name ..
                " parent 1:0 classid 1:1 htb rate " .. rate_ifn[ifn]["rate"] .. "kbit ceil " .. rate_ifn[ifn]["rate"] .. "kbit")

            for i=0,5 do
                rate = rate_res[ifn][i] * rate_ifn[ifn]["rate"] / 100
                rate = math.floor(rate)
                limit = rate_limit[ifn][i] * rate_ifn[ifn]["rate"] / 100

                if i == 5 then
                    --BE class 1:60 prio 6, red queue
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                    " parent 1:1 classid 1:60 htb rate " ..
                    rate .. "kbit ceil " .. limit .. "kbit prio " .. 6)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                    " parent 1:60 red limit 1000000 min 5000 max 100000 avpkt 1000 burst 50")
                else 
                    if i == 0 then
                    --EF class 1:10 prio 1
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                        " parent 1:1 classid 1:10 htb rate " ..
                        rate .. "kbit ceil " .. limit .. "kbit prio " .. 1)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                        " parent 1:10 sfq perturb 10")
                    else
                    --AF4 to AF1, clases 1:20 to 1:50, prio 2 to 5 respectively (high to low)
                    prio = i+1
                    execute(TCBIN .. " class add dev " .. ifn_name  ..
                        " parent 1:1 classid 1:" .. prio .. "0 htb rate " ..
                        rate .. "kbit ceil " .. limit .. "kbit prio " .. prio)
                    execute(TCBIN .. " qdisc add dev " .. ifn_name  ..
                        " parent 1:" .. prio .. "0 sfq perturb 10")
                    end
                end
            end
            --CS1
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x20 0xfc flowid 1:50")
            --AF1x
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x28 0xfc flowid 1:50")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x30 0xfc flowid 1:50")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x38 0xfc flowid 1:50")
            --CS2
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x40 0xfc flowid 1:40")
            --AF2x
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x48 0xfc flowid 1:40")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x50 0xfc flowid 1:40")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x58 0xfc flowid 1:40")
            --CS3
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x60 0xfc flowid 1:30")
            --AF3x
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x68 0xfc flowid 1:30")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x70 0xfc flowid 1:30")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x78 0xfc flowid 1:30")
            --CS4
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x80 0xfc flowid 1:20")
            --AF4x
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x88 0xfc flowid 1:20")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x90 0xfc flowid 1:20")
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0x98 0xfc flowid 1:20")
            --CS5
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0xa0 0xfc flowid 1:10")
            --EF
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0xb8 0xfc flowid 1:10")
            --CS6
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0xc0 0xfc flowid 1:10")
            --CS7
            execute(TCBIN .. " filter add dev " .. ifn_name ..
                " parent 1:0 protocol ip prio 1 u32 match ip tos 0xe0 0xfc flowid 1:10")

        end

        -- Create QoS chain
        iptc_create_chain("mangle", chain_qos)

        --default ICMP and small ACKs EF category, manual entries not required, see priomark4_custom in qos.conf
        --iptables("mangle", "-A " .. chain_qos ..
        --    " -p tcp -m length --length :64 -j DSCP --set-dscp-class EF")
        --iptables("mangle", "-A " .. chain_qos ..
        --    " -p icmp -j DSCP --set-dscp-class EF")

        -- Add configured MARK rules
        for _, rule in ipairs(priomark.ipv4) do
            if tonumber(rule.enabled) == 1 and (rule.ifn == ifn or rule.ifn == '*') then
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
                        "-j DSCP --set-dscp-class " .. rule.prio)
                end
            end
        end

        for _, rule in ipairs(priomark.ipv4_custom) do
            if tonumber(rule.enabled) == 1 and (rule.ifn == ifn or rule.ifn == '*') then
                param = " "
                if tonumber(rule.type) == direction then
                    iptables("mangle", "-A " .. chain_qos .. 
                        " " .. rule.param ..
                        " -j DSCP --set-dscp-class " .. rule.prio)
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
    local ifn_wan
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
    local priomark = { ipv4={}, ipv6={}, ipv4_custom={}, ipv6_custom={} }

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
                    prio=rule[5], param=rule[6]
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
                    prio=rule[5], param=rule[6]
                })
            end
        end
    end

    -- for _, ifn in pairs(WANIF_CONFIG) do
    --    execute(TCBIN .. " qdisc del dev " .. ifn .. " root >/dev/null 2>&1")
    -- end

    rate_up = ParseInterfaceValue(QOS_UPSTREAM)
    rate_down = ParseInterfaceValue(QOS_DOWNSTREAM)
    
    rate_up_res = ParseBandwidthValue(QOS_UPSTREAM_BWRES, rate_up_res)
    rate_up_limit = ParseBandwidthValue(QOS_UPSTREAM_BWLIMIT, rate_up_limit)
    rate_down_res = ParseBandwidthValue(QOS_DOWNSTREAM_BWRES, rate_down_res)
    rate_down_limit = ParseBandwidthValue(QOS_DOWNSTREAM_BWLIMIT, rate_down_limit)

    rate_up_res = InitializeBandwidthReserved(rate_up, rate_up_res)
    rate_up_limit = InitializeBandwidthLimit(rate_up, rate_up_limit)
    rate_down_res = InitializeBandwidthReserved(rate_down, rate_down_res)
    rate_down_limit = InitializeBandwidthLimit(rate_down, rate_down_limit)
    
    if ValidateBandwidthReserved("Reserved upstream", rate_up_res) == false or 
        ValidateBandwidthReserved("Reserved downstream", rate_down_res) == false or 
        ValidateBandwidthLimit("Upstream limit", rate_up_res, rate_up_limit) == false or 
        ValidateBandwidthLimit("Downstream limit", rate_down_res, rate_down_limit) == false then 
        return 
    end 

    for ifn, _ in pairs(rate_up) do
        for __, ifn_wan in pairs(WANIF_CONFIG) do
            if ifn == ifn_wan then
                table.insert(QOS_WANIF, ifn)
            end
        end
    end

    for _, ifn in pairs(QOS_WANIF) do
        rate_up[ifn]["min_rate"] = rate_up[ifn]["rate"]
        rate_down[ifn]["min_rate"] = rate_down[ifn]["rate"]

        for i, rate in pairs(rate_up_res["*"]) do
            rate = rate * rate_up[ifn]["rate"] / 100
            if rate < tonumber(rate_up[ifn]["min_rate"]) then
                rate_up[ifn]["min_rate"] = rate
            end
        end
        for i, rate in pairs(rate_down_res["*"]) do
            rate = rate * rate_down[ifn]["rate"] / 100
            if rate < tonumber(rate_down[ifn]["min_rate"]) then
                rate_down[ifn]["min_rate"] = rate
            end
        end

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

    for _, ifn in pairs(QOS_WANIF) do
        if rate_up[ifn]["r2q"] == "auto" then
            rate_up[ifn]["r2q"] = CalculateRateToQuantum(rate_up[ifn]["min_rate"])
        end
        if rate_down[ifn]["r2q"] == "auto" then
            rate_down[ifn]["r2q"] = CalculateRateToQuantum(rate_down[ifn]["min_rate"])
        end
    end

    QosExecute(0, rate_up, rate_up_res, rate_up_limit, priomark)
    QosExecute(1, rate_down, rate_down_res, rate_down_limit, priomark)
end

-- vi: syntax=lua expandtab shiftwidth=4 softtabstop=4 tabstop=4
