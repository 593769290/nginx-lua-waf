## download file
mkdir -p /usr/local/src
cd /usr/local/src
wget http://nginx.org/download/nginx-1.14.2.tar.gz
wget https://nchc.dl.sourceforge.net/project/pcre/pcre/8.41/pcre-8.41.tar.gz
wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz
wget https://github.com/simpl/ngx_devel_kit/archive/v0.3.0.tar.gz
wget https://github.com/chaoslawful/lua-nginx-module/archive/v0.10.10.zip

#for gfile in `ls *.gz`;do tar xf $gfile;done
#unzip v0.10.10.zip

git clone https://github.com/593769290/nginx-lua-waf.git


## install lua-jit
tar xf LuaJIT-2.0.5.tar.gz
cd LuaJIT-2.0.5
make && make install
ln -s /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
echo "LUAJIT_LIB=/usr/local/lib" >> /etc/profile
echo "LUAJIT_INC=/usr/local/include/luajit-2.0/" >> /etc/profile
source /etc/profile

## install nginx
yum  install -y  wget gcc gcc-c++ gcc-g77 autoconf automake zlib* fiex* libxml*  libmcrypt* libtool-ltdl-devel* make cmake  openssl openssl-devel
cd /usr/local/src
useradd -s /sbin/nologin -M www
tar xf nginx-1.14.2.tar.gz
tar xf pcre-8.41.tar.gz
unzip v0.10.10.zip
tar xf v0.3.0.tar.gz

cd nginx-1.14.2
./configure --user=www --group=www --prefix=/usr/local/nginx-1.14.2 --with-pcre=/usr/local/src/pcre-8.41 --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module  --add-module=../ngx_devel_kit-0.3.0/ --add-module=../lua-nginx-module-0.10.10/
##./configure --user=www --group=www --prefix=/usr/local/nginx-lua-1.14.2 --with-pcre=/usr/local/src/pcre-8.41 --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --with-http_ssl_module --add-module=../ngx_devel_kit-0.3.0/ --add-module=../lua-nginx-module-0.10.10/

make -j2 && make install 
ln -s /usr/local/nginx-1.14.2/ /usr/local/nginx
cd /usr/local/nginx/conf/
mv nginx.conf nginx.conf.bak && egrep -v "^$|#" nginx.conf.bak >> nginx.conf

## config lua-waf  
cd /usr/local/src
#git clone https://github.com/loveshell/ngx_lua_waf.git
#cp -r ngx_lua_waf/ /usr/local/nginx/conf/waf
git clone https://github.com/593769290/nginx-lua-waf.git
cp -a ./nginx-lua-waf/waf /usr/local/nginx/conf/waf
cd /usr/local/nginx/conf/

sed -i '/    server {/i\    lua_package_path "/usr/local/nginx-1.14.2/conf/waf/?.lua";' nginx.conf
sed -i '/    server {/i\    lua_shared_dict limit 100m;' nginx.conf
sed -i '/    server {/i\    init_by_lua_file  /usr/local/nginx-1.14.2/conf/waf/init.lua;' nginx.conf 
sed -i '/    server {/i\    access_by_lua_file /usr/local/nginx-1.14.2/conf/waf/access.lua;' nginx.conf 

mkdir -p /usr/local/nginx-1.14.2/logs/hack
chown -R www.www /usr/local/nginx-1.14.2/logs/hack

/usr/local/nginx/sbin/nginx -t
/usr/local/nginx/sbin/nginx
/usr/local/nginx/sbin/nginx -s reload

## lua-cjson
cd /usr/local/src
wget https://www.kyne.com.au/~mark/software/download/lua-cjson-2.1.0.tar.gz
tar xf lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
##vim Makefile
##LUA_INCLUDE_DIR =   $(PREFIX)/include/luajit-2.0
make install