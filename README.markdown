# Enhanced Nginx Memached Module

Goals
===

This plugin is based on standard [Nginx Memcached plugin](http://wiki.nginx.org/HttpMemcachedModule), with some additonal features : 

* Send custom http headers to client when using memcached cache. Http headers are stored in memcached, before body data.
* Hash keys before inserting ou reading into memcached : allow to use very big keys
* Store data into memcached, with expire time, through http. You can use the `add` or `set` memcached command.
* Delete data from memcached
* Flush memcached
* Get memcached'stats
* Manage key namespaces, for partial memcached flush

Note : base plugin configuration is identical to standard [Nginx Memcached plugin](http://wiki.nginx.org/HttpMemcachedModule).

How to use it
===

Clone the code

    git clone git://github.com/bpaquet/ngx_http_enhanced_memcached_module.git
    
Compile Nginx with option in `./configure`
    
    --add-module=/my/path/to/my/clone/ngx_http_enhanced_memcached_module

Rebuild Nginx, and enjoy !

Note : this plugin has been tested with Nginx 1.1.14, and is used in production at [fasterize](http://www.fasterize.com)

Custom HTTP Headers
===

Instead of inserting raw data in memcached, put something like that

    EXTRACT_HEADERS
    Content-Type: text/xml
    
    <toto></toto>

Memcached module will set the header `Content-Type` to the specified value `text-xml` instead of the default one.
The http body will contains `<toto></toto>`.

Before the body, line delimiters have to be `\r\n`, like in HTTP.

You can add multiple headers if you need.
If you do'nt start with `EXTRACT_HEADERS`, memcached module will only output the content in the http body. 

No modification of nginx config are needed.

Hash keys
===

To avoid problem with big keys in memcached, just add in config :

    enhanced_memcached_hash_keys_with_md5 on;
    
The module will hash key with md5 algorithm before inserting into memcached, and before getting from memcached.

Store data into memcached
===

Add a location in nginx config like that :

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

The second one will take the expire value to set in memcached from http header `Memcached-Expire`.

Use the `add` memcached command
---

If you want to use the `add` memcached command, add following line in config :

    set $enhanced_memcached_use_add 1;

Or 

    set $enhanced_memcached_use_add $http_memcached_use_add;

The first one will always force the use of `add` memcached command.

The second one will use the `add` memcached command only if the http header `Memcached-Use-Add` is present.

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

To fully flush memcached, add a location in nginx config :
    
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

The plugin will use the HTTP host as namespace for the current location.

You can flush a namespace (in reality, it only increment the key prefix) with a location 

    location /flush_ns_to {
      set $enhanced_memcached_key "$request_uri";
      set $enhanced_memcached_key_namespace "$host";
      enhanced_memcached_flush_namespace on;
      enhanced_memcached_pass memcached_upstream;
    }