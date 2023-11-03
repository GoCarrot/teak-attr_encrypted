# frozen_string_literal: true

require 'aws-sdk-kms'

module Teak
  module AttrEncrypted
    module KEKProvider
      class AwsKMS
        KEY_SPEC = 'AES_256'

        def initialize(key_id, client: nil)
          @key_id = key_id
          @kms_client = client || Aws::KMS::Client.new
        end

        def request_data_key(encryption_context)
          parameters = {
            key_id: @key_id,
            key_spec: KEY_SPEC
          }
          if encryption_context
            parameters[:encryption_context] = encryption_context
          end
          @kms_client.generate_data_key(parameters)
        end

        def decrypt_data_key(key, encryption_context)
          parameters = {
            ciphertext_blob: key
          }
          if encryption_context
            parameters[:encryption_context] = encryption_context
          end
          @kms_client.decrypt(parameters)
        end
      end
    end
  end
end
