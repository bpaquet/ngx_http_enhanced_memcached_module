require 'test/unit'

require 'digest/sha1'

require File.join(File.dirname(__FILE__), 'http_test_helper.rb')
require File.join(File.dirname(__FILE__), 'zlib_helper.rb')

class NS < Test::Unit::TestCase

  include HttpTestHelper

  def setup
    init_http "localhost:8086"
    @put_domain = "test01.net.put"
    @std_domain = "test01.net"
    @put_domain2 = "test02.net.put"
    @std_domain2 = "test02.net"
  end

  def assert_stored
    assert_last_response "200", "text/plain", "STORED"
  end

  def test_simple
  	put '/toto', 'this content', @put_domain
  	assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    assert_not_nil @resp['Date']
  end

  def test_simple_multi_domain_and_domain_flush
    delete '/toto', @put_domain
    delete '/toto', @put_domain2

    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    get '/toto', @std_domain2
    assert_not_equal "200", @resp.code
    put '/toto', 'this content2', @put_domain2
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    get '/toto', @std_domain2
    assert_last_response "200", "application/octet-stream", 'this content2'

    get '/flushns', @put_domain2
    assert_equal "200", @resp.code

    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    get '/toto', @std_domain2
    assert_not_equal "200", @resp.code
  end

  def test_specific_headers
    put '/toto', 'myTest', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'myTest'
    get '/toto', @std_domain, {"Pragma" => "no-cache;"}
    assert_not_equal "200", @resp.code
    get '/toto', @std_domain, {"Cache-Control" => "no-cache;"}
    assert_not_equal "200", @resp.code
    head '/toto', @std_domain
    assert_not_equal "200", @resp.code
    assert_not_equal "405", @resp.code
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'myTest'
  end

  def test_very_long_url
    url = '/' + (0..500).map{65.+(rand(25)).chr}.join
    put url, 'this content', @put_domain
    assert_stored
    get url, @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
  end

  def test_flush
    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    put '/toto', 'this content', @put_domain2
    assert_stored
    get '/toto', @std_domain2
    assert_last_response "200", "application/octet-stream", 'this content'

    get '/flush', @put_domain
    assert_last_response "200", "text/plain", 'OK'

    sleep 2

    get '/toto', @std_domain
    assert_not_equal "200", @resp.code
    get '/toto', @std_domain2
    assert_not_equal "200", @resp.code
  end

  def test_simple_short
    put '/toto', '@', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", '@'
  end

  def test_simple_binary
    data = (0...400).map{rand(255).chr}.join.force_encoding('utf-8')
    put '/toto', data, @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", data
    assert_not_nil @resp['Date']
  end

  def test_simple_binary_forcegz
    data = (0...400).map{rand(255).chr}.join.force_encoding('utf-8')
    data_gz = gzip_content data
    put '/toto', data_gz, @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream"
    assert_equal data, gunzip_content(@resp.body)
  end

  def test_empty
    put '/empty', "EXTRACT_HEADERS\r\nContent-Type: application/octet-stream\r\n\r\n", @put_domain
    assert_stored
    get '/empty', @std_domain
    assert_last_response "200", "application/octet-stream", ''
  end

  def test_302
    put '/empty', "EXTRACT_HEADERS\r\nLocation: http://www.google.com\r\nX-Nginx-Status: 302\r\n\r\n", @put_domain
    assert_stored
    get '/empty', @std_domain
    assert_equal "302", @resp.code
    assert_nil @resp['Content-Type']
    assert_nil @resp['X-Nginx-Status']
    assert_equal @resp['Location'], "http://www.google.com"
  end

  def test_99
    put '/empty', "EXTRACT_HEADERS\r\nLocation: http://www.google.com\r\nX-Nginx-Status: 99\r\n\r\n", @put_domain
    assert_stored
    get '/empty', @std_domain
    assert_equal "500", @resp.code
    assert_nil @resp['X-Nginx-Status']
  end


  def test_wrong_status
    put '/empty', "EXTRACT_HEADERS\r\nLocation: http://www.google.com\r\nX-Nginx-Status: abcd\r\n\r\n", @put_domain
    assert_stored
    get '/empty', @std_domain
    assert_equal "500", @resp.code
    assert_nil @resp['X-Nginx-Status']
  end

  def test_image
    png = load_bin_file('show_48.png')
    assert_equal Digest::SHA1.hexdigest(png), '15ad4ab1b2b651cfd04aa83ae251a5ff06e2bf05'
    put '/png', "EXTRACT_HEADERS\r\nContent-Type: image/png\r\n\r\n" + png, @put_domain
    assert_stored
    get '/png', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal Digest::SHA1.hexdigest(@resp.body), '15ad4ab1b2b651cfd04aa83ae251a5ff06e2bf05'
    assert_equal nil, @resp['Content-Encoding']
    assert_not_nil @resp['Date']
  end

  def test_image_content_length
    png = load_bin_file('show_48.png')
    assert_equal Digest::SHA1.hexdigest(png), '15ad4ab1b2b651cfd04aa83ae251a5ff06e2bf05'
    put '/png', "EXTRACT_HEADERS\r\nContent-Length: 6132\r\nContent-Type: image/png\r\n\r\n" + png, @put_domain
    assert_stored
    get '/png', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal Digest::SHA1.hexdigest(@resp.body), '15ad4ab1b2b651cfd04aa83ae251a5ff06e2bf05'
    assert_equal nil, @resp['Content-Encoding']
    assert_not_nil @resp['Date']
  end

  def test_jquery_not_gzipped_by_nginx
    jq = load_bin_file('jquery-1.6.4.js')
    put '/jq', "EXTRACT_HEADERS\r\nContent-Type: application/javascript\r\n\r\n" + jq, @put_domain
    assert_stored
    get '/jq', @std_domain
    assert_last_response "200", "application/javascript", jq
    assert_equal nil, @resp['Content-Encoding']
  end

  def test_jquery_gzipped_by_nginx
    jq = load_bin_file('jquery-1.6.4.js')
    put '/jq', "EXTRACT_HEADERS\r\nContent-Type: application/javascript\r\n\r\n" + jq, @put_domain
    assert_stored
    get '/jq', @std_domain, {'Accept-Encoding' => 'compress, deflate, gzip'}
    assert_last_response "200", "application/javascript"
    assert_equal 'gzip', @resp['Content-Encoding']
    assert_equal jq, gunzip_content(@resp.body)
  end

  def test_jquery_gzipped_by_nginx_with_charset
    jq = load_bin_file('jquery-1.6.4.js')
    put '/jq', "EXTRACT_HEADERS\r\nContent-Type: application/javascript; charset=UTF-8\r\n\r\n" + jq, @put_domain
    assert_stored
    get '/jq', @std_domain, {'Accept-Encoding' => 'compress, deflate, gzip'}
    assert_equal 'gzip', @resp['Content-Encoding']
    assert_equal jq, gunzip_content(@resp.body)
    assert_last_response "200", "application/javascript; charset=UTF-8"
  end

  def test_image_deflate
  	png = load_bin_file('show_48.png')
    deflated_png = Zlib::Deflate.deflate(png)
    put '/png_deflate', "EXTRACT_HEADERS\r\nContent-Type: image/png\r\nContent-Encoding: deflate\r\n\r\n" + deflated_png, @put_domain
    assert_stored
    get '/png_deflate', @std_domain
    assert_equal Digest::SHA1.hexdigest(@resp.body), '15ad4ab1b2b651cfd04aa83ae251a5ff06e2bf05'
    assert_last_response "200", "image/png", png
    assert_equal nil, @resp['Content-Encoding']
  end

  def test_donot_gzip_images
    png = load_bin_file('show_48.png')
    put '/png_deflate', "EXTRACT_HEADERS\r\nContent-Type: image/png\r\n\r\n" + png, @put_domain
    assert_stored
    get '/png_deflate', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal nil, @resp['Content-Encoding']
  end

  def test_image_gzip
    png = load_bin_file('show_48.png')
    gziped = gzip_content png
    put '/png_gzip', "EXTRACT_HEADERS\r\nContent-Type: image/png\r\nContent-Encoding: gzip\r\n\r\n" + gziped, @put_domain
    assert_stored
    get '/png_gzip', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal nil, @resp['Content-Encoding']
  end

  def test_headers
    put '/toto', "EXTRACT_HEADERS\r\nContent-Type: text/plain\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "text/plain", 'this content'
    assert_nil @resp['Toto']
  end

  def test_multiple_headers
    put '/toto', "EXTRACT_HEADERS\r\nToto: tata\r\nContent-Type: text/plain\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "text/plain", 'this content'
    assert_equal 'tata', @resp['Toto']
  end

  def test_extended_content_type
    put '/toto', "EXTRACT_HEADERS\r\nContent-Type: text/css; charset=utf-8\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "text/css; charset=utf-8", 'this content'
  end

  def test_headers_but_no_headers
    put '/toto', "EXTRACT_HEADERS\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
  end

  def test_headers_but_only_that
    put '/toto', "EXTRACT_HEADERS\r\n", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_equal "502", @resp.code
  end

  def test_headers_wrong_format_no_end
    put '/toto_wrong_format_no_end', "EXTRACT_HEADERS\r\nthis content", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end', @std_domain
    assert_equal "502", @resp.code
  end

  def test_wrong_format_no_end_with_one_header_ok
    put '/toto_wrong_format_no_end_with_one_header_ok', "EXTRACT_HEADERS\r\nX-Toto: tata\r\nthis toto", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end_with_one_header_ok', @std_domain
    assert_equal "502", @resp.code
    assert_nil @resp['X-Toto']
  end

  def test_wrong_format_no_end_with_jquery
    put '/toto_wrong_format_no_end_with_jquery', "EXTRACT_HEADERS\r\nthis toto", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end_with_jquery', @std_domain
    assert_equal "502", @resp.code
    jq = load_bin_file('jquery-1.6.4.js')
    put '/jq', "EXTRACT_HEADERS\r\nContent-Type: text/javascript\r\n\r\n" + jq, @put_domain
    assert_stored
    get '/jq', @std_domain
    assert_last_response "200", "text/javascript", jq
    assert_equal nil, @resp['Content-Encoding']
    put '/toto_wrong_format', "EXTRACT_HEADERS\r\nthis toto", @put_domain
    assert_stored
    get '/toto_wrong_format', @std_domain
    assert_equal "502", @resp.code
  end

  def test_wrong_format_no_end_with_colon
    put '/toto_wrong_format_no_end_with_colon', "EXTRACT_HEADERS\r\nthis toto:", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end_with_colon', @std_domain
    assert_equal "502", @resp.code
  end

  def test_wrong_format_no_end_with_colon_and_text
    put '/toto_wrong_format_no_end_with_colon_and_text', "EXTRACT_HEADERS\r\nX-toto: titi", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end_with_colon_and_text', @std_domain
    assert_equal "502", @resp.code
  end

  def test_wrong_format_no_end_with_colon_and_text2
    put '/toto_wrong_format_no_end_with_colon_and_text2', "EXTRACT_HEADERS\r\nthis toto: titi", @put_domain
    assert_stored
    get '/toto_wrong_format_no_end_with_colon_and_text2', @std_domain
    assert_equal "502", @resp.code
  end

  def test_header_no_space_after_colon
    put '/toto_wrong_format', "EXTRACT_HEADERS\r\nthis toto:titi\r\n\r\n", @put_domain
    assert_stored
    get '/toto_wrong_format', @std_domain
    assert_equal "200", @resp.code
    assert_equal "titi", @resp["this toto"]
  end

  def test_headers_wrong_format_no_content
    put '/toto_wrong_format_no_content', "EXTRACT_HEADERS\r\na", @put_domain
    assert_stored
    get '/toto_wrong_format_no_content', @std_domain
    assert_equal "502", @resp.code
  end

  def test_command_not_allowed
    put '/toto', 'this content', @std_domain
    assert_not_equal "200", @resp.code
    assert_not_equal "405", @resp.code
  end

  def test_get_on_extended
    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @put_domain
    assert_last_response "200", "application/octet-stream", 'this content'
  end

  def test_stats
    get '/stats', @put_domain
    assert_equal "200", @resp.code
    assert_equal "text/plain", @resp.content_type
    assert @resp.body.scan(/^STAT .+$/).count > 30
    assert_nil @resp.body.match(/^END/)
  end

  def test_expire
    put '/toto', 'this content', @put_domain, {'Memcached-Expire' => 3}
    assert_stored
    put '/titi', 'this content 2', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    get '/titi', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content 2'
    sleep 4
    get '/toto', @std_domain
    assert_not_equal "200", @resp.code
    get '/titi', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content 2'
  end

  def test_delete
    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    delete '/toto', @put_domain
    assert_last_response "200", "text/plain", 'DELETED'
    get '/toto', @std_domain
    assert_not_equal "200", @resp.code
  end

  # if purge is asked with the wrong domain name (sharded domain name for example), the content is not deleted from cache
  def test_delete_wrong_domain
    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    delete '/toto', 'www.toto.com.put'
    assert_last_response_code "404"
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
  end

 def test_delete_on_non_existent
    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    delete '/toto', @put_domain
    assert_last_response_code "200"
    delete '/toto', @put_domain
    assert_last_response_code "404"
  end

  def test_delete_not_allowed
    delete '/toto', @std_domain
    assert_not_equal "200", @resp.code
    assert_not_equal "405", @resp.code
  end

  def test_multi_put
    put '/toto', 'this content 1', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content 1'
    put '/toto', 'this content 2', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content 2'
  end

  def test_multi_add
    put '/toto', 'this content 1', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content 1'
    put '/toto', 'this content 2', @put_domain, {'Memcached-Use-Add' => "1"}
    assert_last_response_code "409"
  end

  def test_last_modified
    put '/toto', "EXTRACT_HEADERS\r\nMyHeader: tata\r\nLast-Modified: Mon, 23 Apr 2012 13:45:23 GMT\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    get '/toto', @std_domain, {"If-Modified-Since" => "Mon, 22 Apr 2012 13:45:23 GMT"}
    assert_last_response "200", "application/octet-stream", 'this content'
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    get '/toto', @std_domain, {"If-Modified-Since" => "Mon, 23 Apr 2012 13:45:23 GMT"}
    assert_last_response_code "304"
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    assert_nil @resp["Content-Type"]
    assert_nil @resp["Content-Length"]
    assert_nil @resp.body
  end

  def test_last_modified_png
    png = load_bin_file('show_48.png')
    put '/png', "EXTRACT_HEADERS\r\nMyHeader: tata\r\nLast-Modified: Mon, 23 Apr 2012 13:45:23 GMT\r\nContent-Type: image/png\r\n\r\n" + png, @put_domain
    assert_stored
    get '/png', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    get '/png', @std_domain, {"If-Modified-Since" => "Mon, 22 Apr 2012 13:45:23 GMT"}
    assert_last_response "200", "image/png", png
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    get '/png', @std_domain, {"If-Modified-Since" => "Mon, 23 Apr 2012 13:45:23 GMT"}
    assert_last_response_code "304"
    assert_equal "Mon, 23 Apr 2012 13:45:23 GMT", @resp['Last-Modified']
    assert_equal "tata", @resp["MyHeader"]
    assert_nil @resp["Content-Type"]
    assert_nil @resp["Content-Length"]
    assert_nil @resp.body
  end

  def test_if_none_match
    put '/toto', "EXTRACT_HEADERS\r\nMyHeader: tata\r\nETag: foo\r\n\r\nthis content", @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    get '/toto', @std_domain, {"If-None-Match" => "bar"}
    assert_last_response "200", "application/octet-stream", 'this content'
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    get '/toto', @std_domain, {"If-None-Match" => "foo"}
    assert_last_response_code "304"
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    assert_nil @resp["Content-Type"]
    assert_nil @resp["Content-Length"]
    assert_nil @resp.body
  end

  def test_if_none_match_png
    png = load_bin_file('show_48.png')
    put '/png', "EXTRACT_HEADERS\r\nMyHeader: tata\r\nETag: foo\r\nContent-Type: image/png\r\n\r\n" + png, @put_domain
    assert_stored
    get '/png', @std_domain
    assert_last_response "200", "image/png", png
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    get '/png', @std_domain, {"If-None-Match" => "bar"}
    assert_last_response "200", "image/png", png
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    get '/png', @std_domain, {"If-None-Match" => "foo"}
    assert_last_response_code "304"
    assert_equal "foo", @resp['ETag']
    assert_equal "tata", @resp["MyHeader"]
    assert_nil @resp["Content-Type"]
    assert_nil @resp["Content-Length"]
    assert_nil @resp.body
  end

  def test_html_small
    html = load_bin_file('small.html')
    put '/html', "EXTRACT_HEADERS\r\nContent-Type: text/html\r\n\r\n" + html, @put_domain
    assert_stored
    get '/html', @std_domain
    assert_last_response "200", "text/html", html
  end


  def test_html_28k
    html = load_bin_file('issue.html')
    put '/html', "EXTRACT_HEADERS\r\nContent-Type: text/html\r\n\r\n" + html, @put_domain
    assert_stored
    get '/html', @std_domain
    assert_last_response "200", "text/html", html
  end

end
