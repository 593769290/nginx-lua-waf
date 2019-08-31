require 'init'

function waf_main()
    if white_ip_check() then
        return
    elseif white_url_check() then
        return
    elseif black_ip_check() then
        return
    elseif hackip_check(0) then
        return
    elseif protectzone_check() then
        return
    elseif cc_attack_check() then
        return
    elseif url_attack_check() then
        return
    elseif url_args_attack_check() then
        return
    elseif user_agent_attack_check() then
        return
    elseif cookie_attack_check() then
        return
    --elseif post_attack_check() then
    else
        return
    end
end

waf_main()

