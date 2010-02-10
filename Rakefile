require File.dirname(__FILE__) + '/lib/ruby-recaptcha'
require 'rubygems'
require 'rake/clean'
require 'hoe'

# Generate all the Rake tasks
# Run 'rake -T' to see list of generated tasks (from gem root directory)
Hoe.plugins.delete  :rubyforge
Hoe.spec('ruby-recaptcha') do |p|
  description= "A ruby gem interface to help Rails applications use the ReCaptcha service."
  summary= "gem install ruby-recaptcha"
  p.version=RubyRecaptcha::VERSION
  p.developer('McClain Looney', 'm@loonsoft.com')
  p.extra_dev_deps = [
    ['hoe', ">= 2.5.0"]
  ]
  p.clean_globs |= %w[**/.DS_Store tmp *.log **/*.orig **/*~ **/*.swp]
end

Dir['tasks/**/*.rake'].each { |t| load t }

