#!/bin/sh

echo flush_all | nc localhost 11211 | grep OK > /dev/null
if [ $? != 0 ]; then
	echo "Memcached not ready"
	exit 1
fi

memcached -h
ps axu | grep memcached
rm -rf work
mkdir work
mkdir work/logs
if [ "$NGINX_BUILD" != "" ]; then
	set -e
	cd work
	wget http://nginx.org/download/nginx-$NGINX_BUILD.tar.gz
	tar xvzf nginx-$NGINX_BUILD.tar.gz
	cd nginx-$NGINX_BUILD
	./configure --with-debug --add-module=../../../../ngx_http_enhanced_memcached_module
	make
	export NGINX_BIN=$(pwd)/objs/nginx
	set +e
	cd ../../
fi
cp nginx.conf work
$NGINX_BIN -p $(pwd)/work -c nginx.conf
sleep 1

ruby simple_test.rb && ruby ns_test.rb
res=$?

kill $(cat work/nginx.pid)

sleep 1

if [ $res != 0 ]; then
	cat work/logs/*.log
fi

# rm -rf work

exit $res