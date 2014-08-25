
require 'zlib'

def load_bin_file file
   File.open(File.join(File.dirname(__FILE__), 'test_data', file), 'rb') {|io| io.read}.force_encoding("utf-8")
end

def gzip_content content
  buf = StringIO.new
  gz = Zlib::GzipWriter.new(buf)
  gz.write content
  gz.close
  buf.string
end

def gunzip_content content
  Zlib::GzipReader.new(StringIO.new(content)).read
end
