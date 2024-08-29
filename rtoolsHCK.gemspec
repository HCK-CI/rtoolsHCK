# frozen_string_literal: true

require './lib/version'

Gem::Specification.new do |s|
  s.name             = 'rtoolsHCK'
  s.version          = RToolsHCK::VERSION
  s.license          = 'BSD'
  s.required_ruby_version = '>= 3.1.0'

  s.summary          = 'HCK/HLK remote management.'
  s.description      = 'rtoolsHCK: a tool-kit to manage the HCK setup remotely.'

  s.authors          = ['Bishara AbuHatoum', 'Lior Haim', 'Yan Vugenfirer']
  s.email            = 'yvugenfi@redhat.com'
  s.homepage         = 'https://github.com/HCK-CI/rtoolsHCK'

  all_files          = `git ls-files -z`.split("\x0")
  s.files            = all_files.grep(/^(lib|tools)/)
  s.require_paths    = %w[lib tools]

  s.extra_rdoc_files = %w[README.md LICENSE]

  s.add_runtime_dependency('bundler')
  s.add_runtime_dependency('rdoc')
  s.add_runtime_dependency('winrm',      '= 2.3.9')
  s.add_runtime_dependency('winrm-fs',   '= 1.3.5')
  s.metadata['rubygems_mfa_required'] = 'true'
end
