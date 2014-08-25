#!/bin/sh

echo flush_all | nc localhost 11211 | grep OK > /dev/null

rm -rf work
mkdir work
mkdir work/logs
cp nginx.conf work
$NGINX_BIN -p $(pwd)/work -c nginx.conf
sleep 1

ruby cache_test.rb
res=$?

kill $(cat work/nginx.pid)

sleep 1

exit $res