# Enhanced Nginx Memached Module

Goals
===

Main features : 

* Send customs http headers to client when using memcached module. Http headers are stored in memcached, with body data.
* Hash keys before inserting into memcached : allow to have very big keys
* Put data into memcached, with expire time. You can use the `add` or `set` memcached command.
* Delete data from memcached
* Flush memcached
* Get memcached'stats

Note : the third last features are mutually exclusive on the same nginx location.

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

    memcached_hash_keys_with_md5 on;
    
The module will hash key with md5 algorithm before inserting into memcached, and before getting from memcached.

Put data into memcached
===

Add a location in nginx config like that :

    location / {
      set $memcached_key "$request_uri";
      memcached_allow_put on;
      memcached_pass memcached_upstream;
    }
    
And send a PUT HTTP request into nginx, with body containing what you want to store in memcached, under the key $memcached_key. The `set` memcached command is used.

Response is a HTTP code 200, with body containing the string `STORED`.

Note : You can also send get request to this location, data will be extracted from memcached, like in a standard memcached location.

Expiration time
---

Expire time in memcached is set by default to 0.
To set another value, add following line to config :

    set $memcached_expire 2;

Or 

    set $memcached_expire $http_memcached_expire;

The first one will set a fixed expire value (2 seconds).

The second one will take the expire value to set in memcached from http header `Memcached-Expire`.

Use the `add` memcached command
---

If you want to use the `add` memcached command, add following line in config :

    set $memcached_use_add 1;

Or 

    set $memcached_use_add $http_memcached_use_add;

The first one will always force the use of `add` memcached command.

The second one will use the `add` memcached command only if the http header `Memcached-Use-Add` is present.

If you send an `add` command on an existing key, memcached will respond `NOT_STORED`, and the nginx module will issue a HTTP code 409.


Delete data in memcached
===

Add a location in nginx config like that :

    location / {
      set $memcached_key "$request_uri";
      memcached_allow_delete on;
      memcached_pass memcached_upstream;
    }
    
And send a DELETE HTTP request into nginx.

Response is a HTTP code 200, with body containing the string `DELETED`, or HTTP code 404, with body `NOT_FOUND` if the key does not exist in memcached.

Note : It can be used with `memcached_allow_put` in the same location


Flush memcached
===

Add a location in nginx config like that :
    
    location /flush {
      memcached_flush on;
      memcached_pass memcached_upstream;
    }

And send a get request on uri /flush into nginx.

Response is a HTTP code 200, with body containing the string `OK`.

Stats memcached
===

Add a location in nginx config like that :

    location /stats {
      memcached_flush on;
      memcached_pass memcached_upstream;
    }

And send a get request on uri /stats into nginx.

Response is a HTTP code 200, with body containing all stats returned by memcached.

