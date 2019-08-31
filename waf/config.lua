--WAF config file,enable = "on",disable = "off"

--waf status is waf task action or not
config_waf_enable = "off"
--log to file or not
config_log_enable = "on"
--log dir
config_log_dir = "/usr/local/nginx-1.14.2/logs/hack"
--rule setting
config_rule_dir = "/usr/local/nginx-1.14.2/conf/waf/rule-config"
--enable/disable white url
config_white_url_check = "off"
--enable/disable white ip
config_white_ip_check = "off"
--enable/disable block ip
config_black_ip_check = "on"
--enable/disable url check
config_url_check = "on"
--enalbe/disable url args check
config_url_args_check = "on"
--enable/disable user agent check
config_user_agent_check = "off"
--enable/disable cookie deny check
config_cookie_check = "off"
-- protect zone quest check
config_protectzone_check = "off"
config_protectzone_host = {"user.xxx.com", "api.xxx.com"}
config_protectzone_uri = {"/user/sign_in", "/user/sign_up"}
--protect rate aa/bb/cc allow aa time in bb seconds over stop cc seconds
config_protectzone_rate = "20/20/120"
--enable/disable cc check filter same url request frequency
config_cc_check = "on"
--cc rate 60/10/120 allow 60 time in 10 seconds over stop 120 seconds
config_cc_rate = "30/10/120"
--enable/disable hackip check filter all request frequency
config_hackip_check = "on"
--one iprequst rate 80/10/120 allow 100 time in 10 seconds over stop 120 seconds
config_hackip_rate = "80/5/120"
--enable/disable hacker check filter all error in an hour
config_hacker_check = "on"
--one iprequst rate 80/10/120 allow 100 time in 10 seconds over stop 120 seconds
config_hacker_rate = "10/3600/36000"
--enable/disable post check
config_post_check = "off"
--config waf output redirect/html
config_waf_output = "html"
--if config_waf_output ,setting url
config_waf_redirect_url = "https://www.xxxx.com"
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>nginx-waf</title>
</head>
<body>
<h1 align="center"> You are not welcome
</body>
</html>
]]

