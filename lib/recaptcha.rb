#Copyright (c) 2007, 2008, 2009, 2010 McClain Looney
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

require 'openssl'
require 'base64'
require 'cgi'
require 'net/http'
require 'net/https'

module ReCaptcha
  # Some simple view helpers. Include this module in your own helper to pull in macros to spit out view code.
  #   include Recaptcha
  module ViewHelper
    # Call this to generate the actual ReCaptcha script into your template.
    # Options can include
    # [rcc_pub] public recaptcha key (defaults to RCC_PUB constant)
    # [rcc_priv] privte recaptcha key (defaults to RCC_PRIV constant)
    # [ssl] generate ssl-based output, defaults to false
    #
    # This method also sets :rcc_err into the session.
    # Example (rcc_pub and rcc_private not required if RCC_PUB & RCC_PRIV constants are used):
    #       = get_captcha(:rcc_pub => 'foobar', :rcc_priv => 'blegga', :ssl => true)
    #
    def get_captcha(options={})
      k = ReCaptcha::Client.new((options[:rcc_pub] || RCC_PUB), (options[:rcc_priv] || RCC_PRIV), (options[:ssl] || false))
      r = k.get_challenge(session[:rcc_err] || '', options)
      session[:rcc_err]=''
      r
    end

    # Call this to generate the MailHide view code.
    #
    # Note: doesn't currently support ssl for some reason.
    # [address] the email address you want to hide
    # [contents] optional string to display as the text of the mailhide link 
    #
    def mail_hide(address, contents=nil)
      contents = truncate(address,10) if contents.nil?
      k = ReCaptcha::MHClient.new(MH_PUB, MH_PRIV, address)
      enciphered = k.crypted_address
      uri = "http://mailhide.recaptcha.net/d?k=#{MH_PUB}&c=#{enciphered}"
      t =<<-EOF
      <a href="#{uri}"
      onclick="window.open('#{uri}', '', 'toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,width=500,height=300'); return false;" title="Reveal this e-mail address">#{contents}</a>
    EOF
    end

  end

  # This module provides a simple helper for use in your controller
  # to determine whether the ReCaptcha challenge was completed successfully.
  # Simply include this module in your controller class
  module  AppHelper
    # Validate recaptcha  from passed in params. Sets errors into the errors hash.
    #
    # [p] request parameters. Requires :recaptcha_challenge_field and :recaptcha_response_field
    # [errors] errors hash-like thing. Usually ActiveRecord::Base.errors
    # [options] Options hash. currently only uses :rcc_pub and :rcc_priv options for passing in ReCaptcha keys.
    def validate_recap(p, errors, options = {})
      rcc=ReCaptcha::Client.new(options[:rcc_pub] || RCC_PUB, options[:rcc_priv] || RCC_PRIV)
      res = rcc.validate(request.remote_ip, p[:recaptcha_challenge_field], p[:recaptcha_response_field], errors)
      session[:rcc_err]=rcc.last_error
      res
    end
  end

  # Mail hide client. Provides interfaceto ReCaptcha MailHide API
  class MHClient
    # [pubkey] MailHide public key
    # [privkey] MailHide private key
    # [address] the address you want to hide.
    def initialize(pubkey, privkey, address)
      @pubkey=pubkey
      @privkey=privkey
      @address = address
      @host='mailhide.recaptcha.net'
    end
    #The encrypted address
    def crypted_address
      encrypt(@address)
    end
    private
    def encrypt(string)
      padded = pad(string)
      iv="\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
      cipher=OpenSSL::Cipher::Cipher.new("AES-128-CBC")
      binkey = @privkey.unpack('a2'*16).map{|x| x.hex}.pack('c'*16)
      cipher.encrypt
      cipher.key=binkey
      cipher.iv=iv
      ciphertext = []
      cipher.padding=0
      ciphertext = cipher.update(padded)
      ciphertext << cipher.final() rescue nil 
      Base64.encode64(ciphertext).strip.gsub(/\+/, '-').gsub(/\//, '_').gsub(/\n/,'')
    end
    def pad(str)
      l= 16-(str.length%16)
      l.times do
        str<< l
      end
      str
    end
  end

  # This class implements a client object capable of communicating ReCaptcha validation requests to the
  # ReCaptcha service.
  #
  class Client
    #last recaptcha error
    attr_reader :last_error
    # [pubkey]  public ReCaptcha key
    # [privkey] private ReCaptcha key (keep this a secret!)
    # [ssl?] use https for requests when set. defaults to false.
    def initialize(pubkey, privkey, ssl=false)
      @pubkey = pubkey
      @privkey=privkey
      @host = ssl ? 'api-secure.recaptcha.net':'api.recaptcha.net'
      @vhost = 'api-verify.recaptcha.net'
      @proto = ssl ? 'https' : 'http'
      @ssl = ssl
      @last_error=nil
    end

    # get ReCaptcha challenge text, optionally setting the error message displayed on failure.
    # [error] error message to be displayed on error
    # [options] options hash. This is translated into a javascript hash and sent along to the ReCaptcha service as RecaptchaOptions
    #   
    def get_challenge(error='', options={})
      s=''
      if options[:options]
        s << "<script type=\"text/javascript\">\nvar RecaptchaOptions = { "
        options[:options].each do |k,v|
          val = (v.class == Fixnum) ? "#{v}" : "\"#{v}\""
          s << "#{k} : #{val}, "
        end
        s.sub!(/, $/, '};')
        s << "\n</script>\n"
      end
      errslug = (error.empty?||error==nil||error=="success") ? '' :  "&error=#{CGI.escape(error)}"
      s <<<<-EOF
      <script type="text/javascript" src="#{@proto}://#{@host}/challenge?k=#{CGI.escape(@pubkey)}#{errslug}"> </script>
      <noscript>
      <iframe src="#{@proto}://#{@host}/noscript?k=#{CGI.escape(@pubkey)}#{errslug}"
      height="300" width="500" frameborder="0"></iframe><br>
      <textarea name="recaptcha_challenge_field" rows="3" cols="40">
      </textarea>
      <input type="hidden" name="recaptcha_response_field" 
      value="manual_challenge">
      </noscript>
      EOF
    end

    # Validate request. Note that this function actually makes a network request.
    # [remoteip] request remote ip address
    # [challenge] reCaptcha challenge
    # [response] reCaptcha response
    # [errors] errors hash-likethingy (usually from ActiveRecord::Base.errors)
    def validate(remoteip, challenge, response, errors)
      msg = "Captcha failed."
      unless response and challenge
        errors.add_to_base(msg)
        return false
      end
      proxy_host, proxy_port = nil, nil
      proxy_host, proxy_port = ENV['proxy_host'].split(':')  if ENV.has_key?('proxy_host')
      http = Net::HTTP::Proxy(proxy_host, proxy_port).start(@vhost)
      path='/verify'
      data = "privatekey=#{CGI.escape(@privkey)}&remoteip=#{CGI.escape(remoteip)}&challenge=#{CGI.escape(challenge)}&response=#{CGI.escape(response)}"
      resp, data = http.post(path, data, {'Content-Type'=>'application/x-www-form-urlencoded'})
      response = data.split
      result = response[0].chomp
      @last_error=response[1].chomp
      errors.add_to_base(msg) if  result != 'true'
      result == 'true' 
    end
  end

end
