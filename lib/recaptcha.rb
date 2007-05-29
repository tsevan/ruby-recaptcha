#Copyright (c) 2007 McClain Looney
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
  module ViewHelper
    def get_captcha()
      k = ReCaptcha::Client.new(RCC_PUB, RCC_PRIV)
      r = k.get_challenge(session[:rcc_err] || '' )
      session[:rcc_err]=''
      r
    end
    def mail_hide(address, contents=nil)
      contents = truncate(address,10) if contents.nil?
      k = ReCaptcha::MHClient.new(MH_PUB, MH_PRIV)
      enciphered = k.encrypt(address)
      uri = "http://mailhide.recaptcha.net/d?k=#{MH_PUB}&c=#{enciphered}"
      t =<<-EOF
      <a href="#{uri}"
      onclick="window.open('#{uri}', '', 'toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,width=500,height=300'); return false;" title="Reveal this e-mail address">#{contents}</a>
    EOF
    end

  end
  module  AppHelper
    private
    def validate_recap(p, &block)
      rcc=ReCaptcha::Client.new(RCC_PUB, RCC_PRIV)
      res = rcc.validate(request.remote_ip, p[:recaptcha_challenge_field], p[:recaptcha_response_field], &block)
      session[:rcc_err]=rcc.last_error

      res
    end
  end
  class MHClient
    def initialize(pubkey, privkey)
      @pubkey=pubkey
      @privkey=privkey
      @host='mailhide.recaptcha.net'
    end
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
      Base64.encode64(ciphertext).strip.gsub(/\+/, '-').gsub(/\//, '_')
    end
    def pad(str)
      l= 16-(str.length%16)
      l.times do
        str<< l
      end
      str
    end
  end
  class Client

    def initialize(pubkey, privkey, ssl=false)
      @pubkey = pubkey
      @privkey=privkey
      @host = ssl ? 'api-secure.recaptcha.net':'api.recaptcha.net'
      @vhost = 'api-verify.recaptcha.net'
      @proto = ssl ? 'https' : 'http'
      @ssl = ssl
    end

    def get_challenge(error='')
      s=<<-EOF
      <script type="text/javascript" src="#{@proto}://#{@host}/challenge?k=#{CGI.escape(@pubkey)}&error=#{CGI.escape(error)}"> </script>
      <noscript>
      <iframe src="#{@proto}://#{@host}/noscript?k=#{CGI.escape(@pubkey)}"
      height="300" width="500" frameborder="0"></iframe><br>
      <textarea name="recaptcha_challenge_field" rows="3" cols="40">
      </textarea>
      <input type="hidden" name="recaptcha_response_field" 
      value="manual_challenge">
      </noscript>
      EOF
    end

    def last_error
      @last_error
    end
    def validate(remoteip, challenge, response, &block)
      return true if remoteip == '0.0.0.0'
      if not response
        yield 'false'
        return false
      end
      http = Net::HTTP.new(@vhost, 80)
      path='/verify'
      data = "privatekey=#{CGI.escape(@privkey)}&remoteip=#{CGI.escape(remoteip)}&challenge=#{CGI.escape(challenge)}&response=#{CGI.escape(response)}"
      resp, data = http.post(path, data, {'Content-Type'=>'application/x-www-form-urlencoded'})
      response = data.split
      result = response[0].chomp
      @last_error=response[1].chomp
      yield result
      result == 'true' 
    end
  end

end
