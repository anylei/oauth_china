# encoding: utf-8
module OauthChina
  class Douban < OauthChina::OAuth
    attr_accessor :code, :expires_at, :uid, :scope
    def initialize(*args)
      self.consumer_options = {
        :site               => 'https://www.douban.com',
        :authorize_path     => '/service/auth2/auth',
        :access_token_path  => '/service/auth2/token'
      }

      OAuth2::Response.register_parser(:douban, 'text/plain') do |body|
        JSON.parse body
      end

      # super(*args)
      self.code = args[0] if args[0]
    end

    def name
      :douban
    end

    def scope
      default_scope = 'douban_basic_common'
      config['scope'] || default_scope
    end

    def authorized?
      ! self.access_token.nil?
    end

    def authorize(options = {})
      return unless self.code
      self.access_token ||= consumer.auth_code.get_token self.code, :redirect_uri => self.callback, :parse => :douban
    end

    def self.load data
      client =  self.new
      oauth_token = OAuth2::AccessToken.new client.consumer, data[:access_token], {'expires_at'=> data[:expires_at]} if data[:access_token] && data[:expires_at]
      client.access_token = oauth_token
      client
    end

    def dump
      {
        :access_token => access_token.nil? ? nil : access_token.token,
        :expires_at => access_token.nil? ? nil : access_token.expires_at
      }
    end

    def get_uid
      # no need to get uid
    end

    def get_user_info user_url, uid=nil
      self.get(user_url)
    end

    def add_status( data = {})
      type = data.has_key?(:text) ? 'broadcast' : 'recommendation'
      case type
      when 'broadcast'
        data = data.keep_if {|k, v| [:text, :image].include? k}
        # build_multipart_bodies
        if data.has_key? :image
          download_image(data[:image]) do |tf|
            data[:image] = File.open(tf.path)
          end
        end
      when 'recommendation'
        data = data.keep_if {|k, v| [:rec_title, :rec_desc, :rec_url].include? k}
      end

      # add source
      data[:source] = self.key
      data.stringify_keys!
      multipart = build_multipart_bodies data

      begin
        response = self.access_token.post(
          'https://api.douban.com/shuo/v2/statuses/',
          :headers => multipart[:headers],
          :body => multipart[:body]
        )
        response.parsed
      rescue OAuth2::Error
      end

    end

    def get url, params={}
      response = self.access_token.get(url, :params => params.merge({ 'access_token' => self.access_token.token.to_s }), :parse => :douban)
      response.parsed
    end

    def consumer
      @consumer ||= OAuth2::Client.new(key, secret, :site => consumer_options[:site], :authorize_url => consumer_options[:authorize_path], 
                                       :token_url => consumer_options[:access_token_path]) do |b|
        b.request  :multipart
        b.request  :url_encoded
        b.adapter  :net_http
      end
    end

    def authorize_url
      @authorize_url ||= (consumer.auth_code.authorize_url(:redirect_uri => self.callback) + "&scope=#{scope}")
    end

    private

    def download_image image_url
      ext = File.extname(URI.parse(image_url).path)
      ext = '.jpg' if ext.blank?
      tf = Tempfile.new ['img', ext]
      tf.binmode
      begin
        open(image_url){|data| tf.write data.read }
        yield tf
      rescue
      ensure
        tf.close
        tf.unlink
      end
    end

    def mime_type(file)
      case
      when file =~ /\.jpe?g/ then 'image/jpeg'
      when file =~ /\.gif$/ then 'image/gif'
      when file =~ /\.png$/ then 'image/png'
      else 'application/octet-stream'
      end
    end

    CRLF = "\r\n"
    def build_multipart_bodies(parts)
      boundary = Time.now.to_i.to_s(16)
      body = ""
      parts.each do |key, value|
        esc_key = CGI.escape(key.to_s)
        body << "--#{boundary}#{CRLF}"
        if value.respond_to?(:read)
          body << "Content-Disposition: form-data; name=\"#{esc_key}\"; filename=\"#{File.basename(value.path)}\"#{CRLF}"
          body << "Content-Type: #{mime_type(value.path)}#{CRLF*2}"
          body << value.read
        else
          body << "Content-Disposition: form-data; name=\"#{esc_key}\"#{CRLF*2}#{value}"
        end
        body << CRLF
      end
      body << "--#{boundary}--#{CRLF}"
      {
        :body => body,
        :headers => {"Content-Type" => "multipart/form-data; boundary=#{boundary}"}
      }
    end
  end
end
