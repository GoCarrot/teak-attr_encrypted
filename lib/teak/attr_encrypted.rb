# frozen_string_literal: true

require 'teak/attr_encrypted/version'
require 'teak/attr_encrypted/dsl'

module Teak
  module AttrEncrypted
    def self.included(base)
      base.include DSL
    end

    def self.default_kek_provider
      if @default_kek_provider
        @default_kek_provider
      else
        raise Error.new('No key encryption key provider provided!')
      end
    end

    def self.default_kek_provider=(provider)
      @default_kek_provider = provider
    end

    class Error < StandardError; end
    # Your code goes here...
  end
end
