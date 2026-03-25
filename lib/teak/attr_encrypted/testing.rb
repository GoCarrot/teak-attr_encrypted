# frozen_string_literal: true

require 'teak/attr_encrypted'

module Teak
  module AttrEncrypted
    # Test helpers for controlling which encryption contexts are available
    # in test scopes. Prepends onto Encryptor to gate encrypt/decrypt calls.
    module Testing
      # Raised when an encryption context is not allowed in the current test scope.
      class ContextNotAllowed < Teak::AttrEncrypted::Error
        def initialize(context)
          super("Encryption context #{context.inspect} is not allowed in the current test scope")
        end
      end

      THREAD_KEY = :teak_attr_encrypted_testing_config

      class << self
        def allow_encryption_contexts(*contexts)
          config = context_config
          config[:allowed] = contexts.flatten
          config[:denied] = nil
        end

        def deny_encryption_contexts(*contexts)
          config = context_config
          config[:denied] = contexts.flatten
          config[:allowed] = nil
        end

        def context_allowed?(context)
          config = context_config
          if config[:allowed]
            config[:allowed].include?(context)
          elsif config[:denied]
            !config[:denied].include?(context)
          else
            true
          end
        end

        def check_context!(context)
          return if context_allowed?(context)

          raise ContextNotAllowed, context
        end

        def reset!
          Thread.current[THREAD_KEY] = nil
        end

      private

        def context_config
          Thread.current[THREAD_KEY] ||= {}
        end
      end

      # Prepended onto Encryptor to check context before encrypt/decrypt.
      module EncryptorOverride
        def decrypt(envelope, encryption_context)
          Teak::AttrEncrypted::Testing.check_context!(encryption_context)
          super
        end

        def encrypt(plaintext, encryption_context)
          Teak::AttrEncrypted::Testing.check_context!(encryption_context)
          super
        end
      end

      # Include in RSpec to get allow/deny helper methods.
      module RSpecHelpers
        def allow_encryption_contexts(*contexts)
          Teak::AttrEncrypted::Testing.allow_encryption_contexts(*contexts)
        end

        def deny_encryption_contexts(*contexts)
          Teak::AttrEncrypted::Testing.deny_encryption_contexts(*contexts)
        end
      end

      Teak::AttrEncrypted::Encryptor.prepend(EncryptorOverride)
    end
  end
end
