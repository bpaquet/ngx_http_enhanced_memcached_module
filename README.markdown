# Enhanced Nginx Memcached Module

[![Build Status](https://travis-ci.org/bpaquet/ngx_http_enhanced_memcached_module.png)](https://travis-ci.org/bpaquet/ngx_http_enhanced_memcached_module)

Goals
===

This module is based on the standard [Nginx Memcached module](http://wiki.nginx.org/HttpMemcachedModule), with some additonal features:

* Send custom http headers, like `Content-Type`, `Last-Modified`. Http headers are stored in memcached, with your body data.
* Hash keys to use large keys (> 250 chars, memcached limit)
* Store data into memcached, via HTTP request to nginx
* Delete data from memcached, via HTTP request to nginx
* Flush memcached, via HTTP request to nginx
* Get memcached'stats, via HTTP request to nginx
* Manage key namespaces, for partial memcached flush
* Reply `304 Not Modified` for request with `If-Modified-Since` headers and content with `Last-Modified` in cache
* Reply `304 Not Modified` for request with `If-None-Match` headers and content with `ETag` in cache
* Set custom HTTP code to send redirect

You can find some explanations qbout why this module has been created in this [blog post](http://blog.octo.com/en/http-caching-with-nginx-and-memcached/).

Note: base module configuration is identical to the standard [Nginx Memcached module](http://wiki.nginx.org/HttpMemcachedModule).

How to use it
===

Clone the code:

    git clone git://github.com/bpaquet/ngx_http_enhanced_memcached_module.git

Compile Nginx with option in `./configure`, as static or dynamic module

    --add-module=/my/path/to/my/clone/ngx_http_enhanced_memcached_module
    --add-dynamic-module=/my/path/to/my/clone/ngx_http_enhanced_memcached_module

Rebuild Nginx, and enjoy !

You can find configuration example in [tests](https://github.com/bpaquet/ngx_http_enhanced_memcached_module/blob/master/tests/nginx.conf).

This module is tested with Nginx 1.2.x, 1.4.x, 1.6.x, 1.8.x, 1.10.x, 1.11.x and is used in production at [fasterize](http://www.fasterize.com).

Base config
===

This module has the same base configuration than the standard [Nginx Memcached module](http://wiki.nginx.org/HttpMemcachedModule).

All commands and variables are prepfixed by `enhanced`.

* [`enhanced_memcached_pass`](http://wiki.nginx.org/HttpMemcachedModule#memcached_pass)
* [`enhanced_memcached_connect_timeout`](http://wiki.nginx.org/HttpMemcachedModule#memcached_connect_timeout)
* [`enhanced_memcached_read_timeout`](http://wiki.nginx.org/HttpMemcachedModule#memcached_read_timeout)
* [`enhanced_memcached_send_timeout`](http://wiki.nginx.org/HttpMemcachedModule#memcached_send_timeout)
* [`enhanced_memcached_buffer_size`](http://wiki.nginx.org/HttpMemcachedModule#memcached_buffer_size)

* [`$enhanced_memcached_key`](http://wiki.nginx.org/HttpMemcachedModule#.24memcached_key)

Custom HTTP Headers
===

Instead of inserting raw data in memcached, put something like that:

    EXTRACT_HEADERS
    Content-Type: text/xml

    <toto></toto>

Ehanced memcached module will set the header `Content-Type` to the specified value `text-xml` instead of the default one.
The HTTP body will only contains `<toto></toto>`.

Before the body, line delimiters have to be `\r\n`, like in HTTP.

Another example with special chars and two headers:

    EXTRACT_HEADERS\r\n
    Content-Type: text/html\r\n
    Cache-Control:max-age=21600\r\n
    \r\n
    <html><body>toto</body></html>


You can add multiple headers if you need.
If you don't start with `EXTRACT_HEADERS`, enhanced memcached module will only output the content in the HTTP body.

No modification of nginx config is needed.

Status code
===
If you want to send a custom status code, (not a 200), just add the header ``X-Nginx-Status`` in custom headers.
The ehanced memcached module will set the HTTP return code accordingly, and remove this header.

Example, to send a redirect 302:

    EXTRACT_HEADERS\r\n
    Location: http://www.google.com\r\n
    X-Nginx-Status: 302\r\n
    \r\n

Hash keys
===

Memcached keys are limited to 250 chars.
To use largest keys, just add in config :

    enhanced_memcached_hash_keys_with_md5 on;

The enhanced memcached module will hash keys with md5 algorithm before inserting into memcached, and before getting data from memcached.

Store data into memcached
===

Add a location in nginx config like that:

    location / {
      set $enhanced_memcached_key "$request_uri";
      enhanced_memcached_allow_put on;
      enhanced_memcached_pass memcached_upstream;
    }

And send a PUT HTTP request into nginx, with body containing what you want to store in memcached, under the key $enhanced_memcached_key. The `set` memcached command is used.

Response is a HTTP code 200, with body containing the string `STORED`.

Note : You can also send get request to this location, data will be extracted from memcached, like in a standard memcached location.

Expiration time
---

Expire time in memcached is set by default to 0.
To set another value, add following line to config :

    set $enhanced_memcached_expire 2;

Or

    set $enhanced_memcached_expire $http_memcached_expire;

The first one will set a fixed expire value (2 seconds).

The second one will take the expire value to set in memcached from HTTP header `Memcached-Expire`.

Use the `add` memcached command
---

If you want to use the `add` memcached command, add following line in config :

    set $enhanced_memcached_use_add 1;

Or

    set $enhanced_memcached_use_add $http_memcached_use_add;

The first one will always force the use of `add` memcached command.

The second one will use the `add` memcached command only if the HTTP header `Memcached-Use-Add` is present.

If you send an `add` command on an existing key, memcached will respond `NOT_STORED`, and the nginx module will issue a HTTP code 409.


Delete data in memcached
===

To delete entries in memcached,  add a location in nginx config :

    location / {
      set $enhanced_memcached_key "$request_uri";
      enhanced_memcached_allow_delete on;
      enhanced_memcached_pass memcached_upstream;
    }

And send a DELETE HTTP request to this location.

Response is a HTTP code 200, with body containing the string `DELETED`, or HTTP code 404, with body `NOT_FOUND` if the key does not exist in memcached.

Note : It can be used with `enhanced_memcached_allow_put` in the same location


Flush memcached
===

To completely flush memcached, add a location in nginx config :

    location /flush {
      enhanced_memcached_flush on;
      enhanced_memcached_pass memcached_upstream;
    }

And send a GET HTTP request on uri /flush.

Response is a HTTP code 200, with body containing the string `OK`.

Stats memcached
===

To get memcached stats, add a location in nginx config :

    location /stats {
      enhanced_memcached_stats on;
      enhanced_memcached_pass memcached_upstream;
    }

And send a GET HTTP request on uri /stats.

Response is a HTTP code 200, with body containing all stats returned by memcached.

Key namespaces
===

This feature is an implementation of namespaces : see the [memcached documentation](http://code.google.com/p/memcached/wiki/NewProgrammingTricks#Namespacing) for more details.

You can set the namespace to use with a location by adding :

    set $enhanced_memcached_key_namespace "$host";

The enhanced memached module will use the HTTP host as namespace for the current location.

You can flush a namespace (in reality, it only increment the key prefix) with a location

    location /flush_ns_to {
      set $enhanced_memcached_key "$request_uri";
      set $enhanced_memcached_key_namespace "$host";
      enhanced_memcached_flush_namespace on;
      enhanced_memcached_pass memcached_upstream;
    }

304 Not Modified
===

For request with HTTP Header `If-Modified-Since`, and associated resource in memcached with HTTP Header `Last-Modified`, the module will send a 304 Not Modified if resource has not been modified, and if Nginx [configuration](http://wiki.nginx.org/HttpCoreModule#if_modified_since) allows this behaviour.

For request with HTTP Header `If-None-Match`, and associated resource in memcached with HTTP Header `ETag`, the module will send a 304 Not Modified if resource has not been modified.

License
===

Copyright 2012 Bertrand Paquet

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
