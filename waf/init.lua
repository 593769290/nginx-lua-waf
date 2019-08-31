--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--Get WAF rule
function get_rule(rulefilename)
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end

local IP_WHITE_RULE = get_rule('whiteip.rule')
local IP_BLACK_RULE = get_rule('blackip.rule')
local URL_WHITE_RULES = get_rule('whiteurl.rule')
local COOKIE_RULES = get_rule('cookie.rule')
local URL_RULES = get_rule('url.rule')
local ARGS_RULES = get_rule('args.rule')
local USER_AGENT_RULES = get_rule('useragent.rule')
local POST_RULES = get_rule('post.rule')

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--allow white ip
function white_ip_check()
     if config_white_ip_check == "on" then
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    --log_record_txt('White_IP',ngx.var.request_uri,"_","_")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    log_record_txt('BlackList_IP',ngx.var.request_uri,"_","_")
                    if config_waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- protect some url requst frequency
function protectzone_check()
    if config_cc_check == "on" then
        local SERVER_NAME = ngx.var.server_name
        local REQ_URI = ngx.var.request_uri
        local limit = ngx.shared.limit
        local pz_m, err = ngx.re.match(config_protectzone_rate,'([0-9]+)/([0-9]+)/([0-9]+)')
        local PZcount=tonumber(pz_m[1]) --limit count
        local PZseconds=tonumber(pz_m[2]) --time frequency
        local PZlimits=tonumber(pz_m[3]) --deny seconds
        -- check hostname
        local host_in_check = false
        if next(config_protectzone_host) ~= nil then
            for _,chkhost in pairs(config_protectzone_host) do
                if SERVER_NAME == chkhost then
                    host_in_check = true
                    break
                end
            end
         end
        -- check protect url
        if host_in_check then
            if next(config_protectzone_uri) ~= nil then
                for _,chkurl in pairs(config_protectzone_uri) do
                    if startswith(REQ_URI,chkurl) then
                        local PZ_TOKEN = get_client_ip()..chkurl
                        local req,_=limit:get(PZ_TOKEN)
                        if req then
                            if req == PZcount then
                                -- set deny seconds
                                limit:set(PZ_TOKEN, PZcount+1, PZlimits)
                                log_alert_txt('PZone_Attack',get_client_ip(), PZlimits)
                            elseif req > PZcount then
                                log_record_txt('PZone_Attack',ngx.var.request_uri,"-","-")
                                if config_waf_enable == "on" then
                                    ngx.exit(403)
                                end
                                limit:incr(PZ_TOKEN,1)
                                return true
                            else
                                limit:incr(PZ_TOKEN,1)
                            end
                        else
                            limit:set(PZ_TOKEN,1,PZseconds)
                        end
                    end
                end
             end
        end
    end
    return false
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        local cc_m, err = ngx.re.match(config_cc_rate,'([0-9]+)/([0-9]+)/([0-9]+)')
        local CCcount=tonumber(cc_m[1]) --limit count
        local CCseconds=tonumber(cc_m[2]) --time frequency
        local CClimits=tonumber(cc_m[3]) --deny seconds
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req == CCcount then
                -- set deny seconds
                limit:set(CC_TOKEN, CCcount+1, CClimits)
                log_alert_txt('CC_Attack', get_client_ip(), CClimits)
            elseif req > CCcount then
                log_record_txt('CC_Attack',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
                limit:incr(CC_TOKEN,1)
                return true
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end

--checkonly为1表示 只检测值，不创建，不记录，返回检测结果。
--checkonly为0表示 检测值，并记录结果，返回检测结果。
-- 方案1  -- 当前使用
--   每次access均过滤记录IP访问数，hackip_check(0)
--   每次log攻击日志时，不需要 不需要处理 hackip_check(0)
-- 方案2  -- 暂不适用
--   每次access，只核对是否为被封IP hackip_check(1)
--   每次log攻击日志时，如果非HackIP类型，增加hackip_check(0)
function hackip_check(checkonly)
    if config_hackip_check == "on" then
        local HIP_TOKEN = "hackip-"..get_client_ip()
        local limit = ngx.shared.limit
        local hip_m, err = ngx.re.match(config_hackip_rate,'([0-9]+)/([0-9]+)/([0-9]+)')
        local HIPcount=tonumber(hip_m[1]) --limit count
        local HIPseconds=tonumber(hip_m[2]) --time frequency
        local HIPlimits=tonumber(hip_m[3]) --deny seconds
        local req,_=limit:get(HIP_TOKEN)
        if req then
            if req == HIPcount then
                -- set deny seconds
                limit:set(HIP_TOKEN, HIPcount+1, HIPlimits)
                log_alert_txt('Deny_HackIP', get_client_ip(), HIPlimits)
            elseif req > HIPcount  then
                log_record_txt('Deny_HackIP',ngx.var.request_uri,"-","-")
                if config_waf_enable == "on" then
                    ngx.exit(403)
                end
                if checkonly ~=1 then limit:incr(HIP_TOKEN,1)  end
                return true
            else
                if checkonly ~=1 then limit:incr(HIP_TOKEN,1)  end
             end
        else
            if checkonly ~=1 then limit:set(HIP_TOKEN,1,HIPseconds)  end
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record_txt('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        --waf_output()
                        ngx.exit(403)
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record_txt('Deny_URL',REQ_URI,"-",rule)
                if config_waf_enable == "on" then
                    --waf_output()
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record_txt('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        --waf_output()
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
    return false
end
--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record_txt('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if config_waf_enable == "on" then
                        --waf_output()
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post not finish not test not use
function post_attack_check()
    if config_post_check == "on" then
        for _,rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

