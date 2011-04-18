# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{ruby-recaptcha}
  s.version = "1.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["McClain Looney", "Vitaly Tsevan"]
  s.date = %q{2011-04-18}
  s.description = %q{A ruby gem interface to help Rails applications use the ReCaptcha service.}
  s.extra_rdoc_files = [
    "README.txt"
  ]
  s.files = [
    "Manifest.txt",
    "README.txt",
    "Rakefile",
    "VERSION",
    "lib/recaptcha.rb",
    "lib/ruby-recaptcha.rb",
    "ruby-recaptcha.gemspec",
    "script/console",
    "script/destroy",
    "script/generate",
    "scripts/txt2html",
    "setup.rb",
    "test/test_helper.rb",
    "test/test_recaptcha.rb",
    "website/index.txt"
  ]
  s.homepage = %q{https://github.com/tsevan/ruby-recaptcha}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.7}
  s.summary = %q{My Fork of https://bitbucket.org/mml/ruby-recaptcha. A ruby gem interface to help Rails applications use the ReCaptcha service.}
  s.test_files = [
    "test/test_helper.rb",
    "test/test_recaptcha.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end

