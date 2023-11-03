# frozen_string_literal: true

require 'teak/attr_encrypted/kek_provider/aws_kms'
require 'securerandom'

RSpec.describe Teak::AttrEncrypted::KEKProvider::AwsKMS do
  let(:client) { Aws::KMS::Client.new(stub_responses: true) }
  let(:key_id) { SecureRandom.uuid }
  subject(:kek_provider) { described_class.new(key_id, client: client) }

  describe '#request_data_key' do
    it 'generates a data key with the key id for AES_256' do
      kek_provider.request_data_key(nil)
      expect(client.api_requests).to contain_exactly(
        hash_including(
          operation_name: :generate_data_key,
          params: {
            key_id: key_id,
            key_spec: 'AES_256'
          }
        )
      )
    end

    it 'provides encryption context when given' do
      kek_provider.request_data_key('foo' => 'bar', 'baz' => 'boo')
      expect(client.api_requests).to contain_exactly(
        hash_including(
          operation_name: :generate_data_key,
          params: {
            key_id: key_id,
            key_spec: 'AES_256',
            encryption_context: { 'foo' => 'bar', 'baz' => 'boo' }
          }
        )
      )
    end

    it 'returns a structure with plaintext and ciphertext_blob attributes' do
      expect(kek_provider.request_data_key(nil)).to have_attributes(
        plaintext: anything,
        ciphertext_blob: anything
      )
    end
  end

  describe '#decrypt_data_key' do
    it 'passes the key in for decryption' do
      key = SecureRandom.hex
      kek_provider.decrypt_data_key(key, nil)
      expect(client.api_requests).to contain_exactly(
        hash_including(
          operation_name: :decrypt,
          params: {
            ciphertext_blob: key
          }
        )
      )
    end

    it 'provides encryption context when given' do
      key = SecureRandom.hex
      kek_provider.decrypt_data_key(key, 'foo' => 'bar', 'baz' => 'boo')
      expect(client.api_requests).to contain_exactly(
        hash_including(
          operation_name: :decrypt,
          params: {
            ciphertext_blob: key,
            encryption_context: { 'foo' => 'bar', 'baz' => 'boo' }
          }
        )
      )
    end

    it 'returns a structure with plaintext attribute' do
      expect(kek_provider.decrypt_data_key(SecureRandom.hex, nil)).to have_attributes(
        plaintext: anything
      )
    end
  end
end
