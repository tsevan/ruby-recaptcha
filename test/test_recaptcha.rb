require File.dirname(__FILE__) + '/test_helper.rb'

class TestRecaptcha < Test::Unit::TestCase

  def setup
  end
  
  def test_constructor
    client = ReCaptcha::Client.new('abc', 'def', true)
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"https://api-secure.recaptcha.net/challenge?k=abc&error=\"> </script>\n      <noscript>\n      <iframe src=\"https://api-secure.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
    client = ReCaptcha::Client.new('abc', 'def', false)
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"http://api.recaptcha.net/challenge?k=abc&error=\"> </script>\n      <noscript>\n      <iframe src=\"http://api.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
    client = ReCaptcha::Client.new('abc', 'def')
    expected= <<-EOF
    <script type=\"text/javascript\" src=\"http://api.recaptcha.net/challenge?k=abc&error=\"> </script>\n      <noscript>\n      <iframe src=\"http://api.recaptcha.net/noscript?k=abc\"\n      height=\"300\" width=\"500\" frameborder=\"0\"></iframe><br>\n      <textarea name=\"recaptcha_challenge_field\" rows=\"3\" cols=\"40\">\n      </textarea>\n      <input type=\"hidden\" name=\"recaptcha_response_field\" \n      value=\"manual_challenge\">\n      </noscript>
    EOF
    assert_equal expected.strip, client.get_challenge.strip
  end

  def test_validate
    #bad test, this just validates that the logic to short-circuit
    #the validate process works right.
    #due to the nature of captcha,really validating would be quite a bit of work.
    client = ReCaptcha::Client.new('abc', 'def')
    assert client.validate('0.0.0.0', 'abc', 'def', nil)
  end
end
