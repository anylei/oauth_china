module OauthChina
  class Sina < OauthChina::OAuth

    attr_accessor :code, :expires_at, :uid
    def initialize(*args)
      self.consumer_options = {
        :site               => 'https://api.weibo.com',
        :access_token_path  => '/oauth2/access_token',
        :authorize_path     => '/oauth2/authorize'
      }

      # add oauth2 weibo parser
      OAuth2::Response.register_parser(:sina, 'text/plain') do |body|
        JSON.parse body
      end
      # super(*args)
      if args[0]
        self.code = args[0]
      else

      end
    end

    def name
      :sina
    end

    def authorized?
      #TODO
      ! self.access_token.nil?
    end

    def destroy
      #TODO
    end
    #QQ和新浪OAuth需要verifier参数，豆瓣不需要
    def authorize(options = {})
      return unless self.code
      self.access_token ||= consumer.auth_code.get_token self.code, :redirect_uri => self.callback, :parse => :sina
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

    def get url, params={}
      self.access_token.get(url, :params => params.merge({ 'access_token' => self.access_token.token.to_s }))
    end

    def post url, params={}
      self.access_token.post(url, :params => params.merge({ 'access_token' => self.access_token.token.to_s }))
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
      @authorize_url ||= consumer.auth_code.authorize_url(:redirect_uri => self.callback)
    end

    def add_status(content, options = {})
      options.merge!(:status => content)
      self.post("https://api.weibo.com/2/statuses/update.json", options)
    end

    def get_uid
      JSON.parse(get("https://api.weibo.com/2/account/get_uid.json").body)["uid"]
    end

    def upload_image(content, image_path, options = {})
      begin
        data = {"status" => content, "pic" => File.open(image_path)}
        multipart = build_multipart_bodies data
        response = self.access_token.post('https://upload.api.weibo.com/2/statuses/upload.json', :headers => multipart[:headers], :body => multipart[:body], :params => {'access_token' => self.access_token.token.to_s})
      rescue OAuth2::Error => e
        puts e
      end
    end

    def get_user_info user_url, uid
      JSON.parse self.get(user_url,{:uid => uid}).body
    end

    private
    def mime_type(file)
      case
      when file =~ /\.jpg/ then 'image/jpg'
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
      body << "--#{boundary}--#{CRLF*2}"
      {
        :body => body,
        :headers => {"Content-Type" => "multipart/form-data; boundary=#{boundary}"}
      }
    end
  end
end
