# nginx-lua-waf

####项目来源：
综合参考多个项目ngx_lua_waf，请先参阅其下项目说明。
https://github.com/loveshell/ngx_lua_waf
https://github.com/unixhot/waf
https://github.com/weakestan/ngx_lua_waf
https://github.com/losingle/ngx_lua_waf


####安装流程：
基本安装流程，请根据需要做相应调整
nginx-lua-install.sh
安装参考资料
https://blog.51cto.com/ityunwei2017/2154753
https://blog.oldboyedu.com/nginx-waf/

####功能列表：
白名单类
1.	支持IP白名单和黑名单功能，直接将黑名单的IP访问拒绝。
2.	支持URL白名单，将不需要过滤的URL进行定义。
单项过滤类
3.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
4.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
5.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
6.	支持URL参数过滤，原理同上。
访问频率控制类
7.	支持重点保持URL CC攻击防护，限制单个URL指定时间的访问次数，超过设定值，直接返回403。
     20/20/120  同ip访问同一地址超过20次/20秒，限制该ip访问nginx服务器120秒。
8.	支持简单URL CC攻击防护，限制单个URL指定时间的访问次数，超过设定值，直接返回403。
     30/10/120  同ip访问同一地址超过30次/10秒，限制该ip访问nginx服务器120秒。
9.	拦截攻击IP：拦截IP访问频率
     80/5/120  同ip访问服务器超过80次/5秒，限制该ip访问nginx服务器120秒。	 
	 
####项目使用提醒：
该项目有很多不完善的地方，也可能没有时间维护，整理在此，尽供学习使用，实践使用请自行测试调整。
有好的提议，欢迎提issues。	 
