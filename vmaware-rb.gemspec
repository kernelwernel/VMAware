# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = 'vmaware-rb'
  spec.version     = '1.0.0'
  spec.summary     = "A ruby wrapper around the VMAware C++ library's default functionality. "
  spec.authors = 'Adam Ruman'
  
  spec.extensions = ['gem/extension/CMakeLists.txt']
  spec.require_paths = ['gem/lib']

  spec.files = Dir.chdir(__dir__) { Dir[
    'LICENSE',
    'gem/extension/include/rice/rice.hpp',
    'gem/extension/CMakeLists.txt',
    'gem/extension/vmaware-rb.hpp',
    'gem/extension/vmaware-rb.cpp',
    'gem/lib/vmaware-rb.rb',
    'src/vmaware.hpp'
  ] }

  spec.required_ruby_version = '>= 3.3'
  spec.metadata['rubygems_mfa_required'] = 'true'

end
