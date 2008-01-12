require File.dirname(__FILE__) + '/test_helper.rb'
require 'rubygems'
gem 'mocha'
require 'mocha'
gem 'rails'

class TestRecaptcha < Test::Unit::TestCase
  class ViewFixture
    PRIVKEY='6LdnAQAAAAAAAPYLVPwVvR7Cy9YLhRQcM3NWsK_C'
    PUBKEY='6LdnAQAAAAAAAKEk59yjuP3csGEeDmdj__7cyMtY'
    include ReCaptcha::ViewHelper
  end

  def setup
    @vf = ViewFixture.new
  end

  def test_encrypt
    mhc = ReCaptcha::MHClient.new('01S1TOX9aibKxfC9oJlp8IeA==', 'deadbeefdeadbeefdeadbeefdeadbeef')
    z =mhc.encrypt('x@example.com')
    assert_equal 'wBG7nOgntKqWeDpF9ucVNQ==', z
    z =mhc.encrypt('johndoe@example.com')
    assert_equal 'whWIqk0r4urZ-3S7y7uSceC9_ECd3hpAGy71E2o0HpI=', z
  end

  def test_constructor
    client = new_client('abc', 'def', true)
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"https://api-secure.recaptcha.net/challenge?k=abc\"> </script>\n      <noscript>\n      <iframe src=\"https://api-secure.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
    client = new_client
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"http://api.recaptcha.net/challenge?k=abc\"> </script>\n      <noscript>\n      <iframe src=\"http://api.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
    client = new_client
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"http://api.recaptcha.net/challenge?k=abc\"> </script>\n      <noscript>\n      <iframe src=\"http://api.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
  end
  
  def test_constructor_with_recaptcha_options
    # "Look and Feel Customization" per http://recaptcha.net/apidocs/captcha/
    client = new_client
    expected= <<-EOF
    <script type=\"text/javascript\">\nvar RecaptchaOptions = { theme : \"white\", tabindex : 10};\n</script>\n      <script type=\"text/javascript\" src=\"http://api.recaptcha.net/challenge?k=abc&error=somerror\"> </script>\n      <noscript>\n      <iframe src=\"http://api.recaptcha.net/noscript?k=abc&error=somerror\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge('somerror', :options => {:theme => 'white', :tabindex => 10}).strip
  end

  def test_validate_fails
    badwords_resp="false\r\n360 incorrect-captcha-sol"
    err_stub=mock()
    err_stub.expects(:add_to_base).with("Captcha failed.")
    stub_proxy=mock('proxy')
    stub_http = mock('http mock')
    stub_proxy.expects(:start).with('api-verify.recaptcha.net').returns(stub_http)
    stub_http.expects(:post).with('/verify', 'privatekey=def&remoteip=localhost&challenge=abc&response=def', {'Content-Type' => 'application/x-www-form-urlencoded'}).returns(['foo', badwords_resp])
    Net::HTTP.expects(:Proxy).returns(stub_proxy)
    client = new_client
    assert !client.validate('localhost', 'abc', 'def', err_stub)
  end
  def test_validate_good
    goodwords_resp="true\r\nsuccess"
    err_stub=mock()
    stub_proxy=mock('proxy')
    stub_http = mock('http mock')
    stub_proxy.expects(:start).with('api-verify.recaptcha.net').returns(stub_http)
    stub_http.expects(:post).with('/verify', 'privatekey=def&remoteip=localhost&challenge=abc&response=def', {'Content-Type' => 'application/x-www-form-urlencoded'}).returns(['foo', goodwords_resp])
    Net::HTTP.expects(:Proxy).with(nil, nil).returns(stub_proxy)
    client = new_client
    assert client.validate('localhost', 'abc', 'def', err_stub)
  end
  def test_validate_good_proxy
    ENV['proxy_host']='fubar:8080'
    goodwords_resp="true\r\nsuccess"
    err_stub=mock()
    stub_proxy=mock('proxy')
    stub_http = mock('http mock')
    stub_proxy.expects(:start).with('api-verify.recaptcha.net').returns(stub_http)
    stub_http.expects(:post).with('/verify', 'privatekey=def&remoteip=localhost&challenge=abc&response=def', {'Content-Type' => 'application/x-www-form-urlencoded'}).returns(['foo', goodwords_resp])
    Net::HTTP.expects(:Proxy).with('fubar', '8080').returns(stub_proxy)
    client = new_client
    assert client.validate('localhost', 'abc', 'def', err_stub)
    ENV['proxy_host']='fubar'
    err_stub=mock()
    stub_proxy=mock('proxy')
    stub_http = mock('http mock')
    stub_proxy.expects(:start).with('api-verify.recaptcha.net').returns(stub_http)
    stub_http.expects(:post).with('/verify', 'privatekey=def&remoteip=localhost&challenge=abc&response=def', {'Content-Type' => 'application/x-www-form-urlencoded'}).returns(['foo', goodwords_resp])
    Net::HTTP.expects(:Proxy).with('fubar', nil).returns(stub_proxy)
    client = new_client
    assert client.validate('localhost', 'abc', 'def', err_stub)
  end
  
private

  def new_client(pubkey='abc', privkey='def', ssl=false)
    ReCaptcha::Client.new(pubkey, privkey, ssl)
  end
end
