require 'net/http'

module HttpTestHelper

  def init_http host
    @ip, @port = host.split(':')
    @port ||= "80"
  end

  def set_basic_auth username, password
    @username = username
    @password = password
  end

  def enable_cookies
    @cookies = {}
  end

  def get uri, host = nil, headers = {}
    req = Net::HTTP::Get.new(uri)
    send_req req, host, headers
  end

  def head uri, host = nil, headers = {}
    req = Net::HTTP::Head.new(uri)
    send_req req, host, headers
  end

  def delete uri, host = nil, headers = {'Content-Length' => '0'}, body = nil
    req = Net::HTTP::Delete.new(uri)
    req.body = body
    send_req req, host, headers
  end

  def post uri, body, host = nil, headers = {}
    req = Net::HTTP::Post.new(uri)
    req.body = body
    send_req req, host, headers
  end

  def put uri, body, host = nil, headers = {}
    req = Net::HTTP::Put.new(uri)
    req.body = body
    send_req req, host, headers
  end

  def assert_last_response_code code
    assert_equal code.to_i, @resp.code.to_i
  end

  def assert_last_response_header header, value
    assert_equal value, @resp[header]
  end

  def assert_last_response_content body = nil
    assert_equal body, @resp.body
  end

  def assert_last_response code, content_type, body = nil
    assert_last_response_code code
    assert_equal content_type, @resp['Content-Type']
    if body
      assert_not_nil @resp.body.size
      assert_equal body.size, @resp.body.size
      assert_equal body, @resp.body
    end
  end

  def resp
    @resp
  end

  def to_s
    "#{@ip}:#{@port}"
  end

  private

  def send_req req, host, headers
    req.basic_auth @username, @password if @username && @password
    if @cookies
      @cookies.each do |name, cookie|
        req.add_field 'Cookie', "#{cookie.name}=#{cookie.value}"
      end
    end
    req['Host'] = host if host
    headers.each do |k, v|
      req[k] = v
    end
    Net::HTTP.start(@ip, @port) do |http|
      @resp = http.request(req)
      @last_request_path = req.path
    end
    if @cookies
      cookies = @resp.get_fields('Set-Cookie') || []
      cookies.each do |cookie|
        parsed = HttpCookie.new cookie
        @cookies[parsed.name] = parsed
      end
    end
    @resp.body.force_encoding('utf-8') if @resp.body
    @resp
  end

end

class HttpCookie

  attr_reader :name, :value, :path

  def initialize s
    s.split(';').each do |k|
      name, value = k.split('=').map{|z| z.strip}
      if name == "Path"
        @path = value
      elsif @name
        raise "Unable to parse #{s}, key #{k}"
      else
        @name = name
        @value = value
      end
    end
  end

end

