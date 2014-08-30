require 'test/unit'

require 'digest/sha1'

require File.join(File.dirname(__FILE__), 'http_test_helper.rb')
require File.join(File.dirname(__FILE__), 'zlib_helper.rb')

class Simple < Test::Unit::TestCase

  include HttpTestHelper

  def setup
    init_http "localhost:8087"
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

  def test_simple_multi_domain
    delete '/toto', @put_domain
    delete '/toto', @put_domain2

    put '/toto', 'this content', @put_domain
    assert_stored
    get '/toto', @std_domain
    assert_last_response "200", "application/octet-stream", 'this content'
    get '/toto', @std_domain2
    assert_last_response "200", "application/octet-stream", 'this content'
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

  def test_serve_static
    get '/small.html', @std_domain
    assert_last_response "200", "text/html", load_bin_file('small.html')
    get '/small2.html', @std_domain
    assert_last_response "404", "text/html"
  end

end
