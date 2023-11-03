# frozen_string_literal: true

require 'teak/attr_encrypted/encryptor'

module Teak
  module AttrEncrypted
    module DSL
      def self.included(base)
        base.extend ClassMethods
      end

      module ClassMethods
        def attr_encrypted(attr_name, ciphertext_attr_name: nil, kek_provider: nil, context: nil)
          real_field = ciphertext_attr_name || "#{attr_name}_enc"
          real_field_assign = "#{real_field}="
          encryptor = Teak::AttrEncrypted::Encryptor.new(kek_provider || Teak::AttrEncrypted.default_kek_provider)

          context_callable =
            if context.is_a?(Symbol)
              proc { send(context) }
            elsif context.is_a?(Proc)
              context
            else
              proc { context }
            end

          define_method "#{attr_name}=" do |value|
            if value.nil? || value.empty?
              send(real_field_assign, value)
              return value
            end

            send(real_field_assign, encryptor.encrypt(value, instance_exec(&context_callable)))
          end

          define_method attr_name do
            envelope = send(real_field)
            if envelope.nil? || envelope.empty?
              envelope
            else
              encryptor.decrypt(send(real_field), instance_exec(&context_callable))
            end
          end
        end
      end
    end
  end
end
