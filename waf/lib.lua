--waf core lib
require 'config'

--Get the client IP
function get_client_ip()
    CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

--Get the client user agent
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

function startswith(str, substr)
    if str == nil or substr == nil then
        return nil, "the string or the sub-stirng parameter is nil"
    end
    if string.find(str, substr) ~= 1 then
        return false
    else
        return true
    end
end

--WAF log record for txt,(use logstash codec => txt)
function log_record_txt(rulename,url,data,ruletag)
    if config_log_enable == "on" then
        local LOG_PATH = config_log_dir
        local CLIENT_IP = get_client_ip()
        local USER_AGENT = get_user_agent()
        local SERVER_NAME = ngx.var.server_name
        local LOCAL_TIME = ngx.localtime()

        LOG_LINE = rulename.." "..LOCAL_TIME.." "..CLIENT_IP.." \""..SERVER_NAME..url.."\"  \""..USER_AGENT.."\" \""..data.."\" \""..ruletag.."\"\n"
        local LOG_NAME = LOG_PATH..'/waf_'..SERVER_NAME.."_"..ngx.today()..".log"
        local file = io.open(LOG_NAME,"a")
        if file == nil then
            return
        end
        file:write(LOG_LINE)
        file:flush()
        file:close()
        -- add hackip count
        --if config_hackip_check == "on" then
        --    if rulename ~= "Deny_HackIP" then hackip_check(0) end
        --end
    end
end

--WAF log alert for txt,(use logstash codec => txt)
function log_alert_txt(rulename,client_ip,limit)
    if config_log_enable == "on" then
        local LOG_PATH = config_log_dir
        local SERVER_NAME = ngx.var.server_name
        local LOCAL_TIME = ngx.localtime()
        LOG_LINE = rulename.." "..client_ip.." "..LOCAL_TIME.." "..SERVER_NAME.." deny "..limit.."\n"
        local LOG_NAME = LOG_PATH..'/alert_'..SERVER_NAME.."_"..ngx.today()..".log"
        local file = io.open(LOG_NAME,"a")
        if file == nil then
            return
        end
        file:write(LOG_LINE)
        file:flush()
        file:close()
    end
end

--WAF log record for json,(use logstash codec => json)
function log_record_json(rulename,url,data,ruletag)
    if config_log_enable == "on" then
        local cjson = require("cjson")
        local io = require 'io'
        local LOG_PATH = config_log_dir
        local CLIENT_IP = get_client_ip()
        local USER_AGENT = get_user_agent()
        local SERVER_NAME = ngx.var.server_name
        local LOCAL_TIME = ngx.localtime()
        local log_json_obj = {
                     client_ip = CLIENT_IP,
                     local_time = LOCAL_TIME,
                     server_name = SERVER_NAME,
                     user_agent = USER_AGENT,
                     attack_method = rulename,
                     req_url = url,
                     req_data = data,
                     rule_tag = ruletag,
                  }
        local LOG_LINE = cjson.encode(log_json_obj)
        local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"
        local file = io.open(LOG_NAME,"a")
        if file == nil then
            return
        end
        file:write(LOG_LINE.."\n")
        file:flush()
        file:close()
    end
end

--WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end

