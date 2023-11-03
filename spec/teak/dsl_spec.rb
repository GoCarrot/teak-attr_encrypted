# frozen_string_literal: true

require 'teak/attr_encrypted'
require 'teak/attr_encrypted/kek_provider/aes'
require 'securerandom'

RSpec.describe Teak::AttrEncrypted::DSL do
  let(:plaintext) { SecureRandom.hex }
  let(:ciphertext_attr_name) { :test_attr_enc }
  subject(:instance) { klass.new }

  shared_examples_for 'basic functioning' do
    it 'roundtrips' do
      instance.test_attr = plaintext
      expect(instance.test_attr).to eq plaintext
    end

    it 'sets the encrypted attribute' do
      instance.test_attr = plaintext
      expect(instance.send(ciphertext_attr_name)).not_to be_empty
    end

    it 'relies on the encrypted attribute' do
      instance.test_attr = plaintext
      instance.send("#{ciphertext_attr_name}=", instance.send(ciphertext_attr_name).succ)
      expect { instance.test_attr }.to raise_error(StandardError)
    end

    it 'handles being set to nil' do
      instance.test_attr = nil
      expect(instance.test_attr).to be nil
    end

    it 'handles being set to empty string' do
      instance.test_attr = ''
      expect(instance.test_attr).to eq ''
    end
  end

  context 'with a kek provider given' do
    class TestClass
      include Teak::AttrEncrypted

      attr_accessor :test_attr_enc
      attr_encrypted :test_attr, kek_provider: Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key)
    end

    let(:klass) { TestClass }

    include_examples 'basic functioning'
  end

  context 'with a custom ciphertext attribute name' do
    let(:ciphertext_attr_name) { :my_super_secret_storage }
    class CustomTestClass
      include Teak::AttrEncrypted

      attr_accessor :my_super_secret_storage
      attr_encrypted :test_attr,
                     kek_provider: Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key),
                     ciphertext_attr_name: :my_super_secret_storage
    end

    let(:klass) { CustomTestClass }

    include_examples 'basic functioning'
  end

  context 'with no kek provider' do
    it 'raises an error' do
      expect do
        Class.new do
          include Teak::AttrEncrypted

          attr_accessor :test_attr_enc
          attr_encrypted :test_attr
        end
      end.to raise_error(Teak::AttrEncrypted::Error)
    end
  end

  context 'with a default kek provider' do
    before do
      Teak::AttrEncrypted.default_kek_provider = Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key)
    end

    after do
      Teak::AttrEncrypted.default_kek_provider = nil
    end

    let(:klass) do
      Class.new do
        include Teak::AttrEncrypted

        attr_accessor :test_attr_enc
        attr_encrypted :test_attr
      end
    end

    include_examples 'basic functioning'
  end

  context 'with a symbol encryption context' do
    class SymbolContextTestClass
      include Teak::AttrEncrypted

      def initialize(context)
        self.test_context = context
      end

      attr_accessor :test_attr_enc
      attr_accessor :test_context
      attr_encrypted :test_attr,
                     kek_provider: Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key),
                     context: :test_context
    end

    let(:klass) { SymbolContextTestClass }
    subject(:instance) { klass.new(SecureRandom.hex) }

    include_examples 'basic functioning'

    it 'relies on the context' do
      instance.test_attr = plaintext
      instance.test_context = instance.test_context.succ
      expect { instance.test_attr }.to raise_error(StandardError)
    end
  end

  context 'with a proc encryption context' do
    class ProcContextTestClass
      include Teak::AttrEncrypted

      def initialize(context)
        self.test_context = context
      end

      attr_accessor :test_attr_enc
      attr_accessor :test_context
      attr_encrypted :test_attr,
                     kek_provider: Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key),
                     context: -> { test_context }
    end

    let(:klass) { ProcContextTestClass }
    subject(:instance) { klass.new(SecureRandom.hex) }

    include_examples 'basic functioning'

    it 'relies on the context' do
      instance.test_attr = plaintext
      instance.test_context = instance.test_context.succ
      expect { instance.test_attr }.to raise_error(StandardError)
    end
  end

  context 'with a fixed encryption context' do
    class FixedContextTestClass
      include Teak::AttrEncrypted

      attr_accessor :test_attr_enc
      attr_encrypted :test_attr,
                     kek_provider: Teak::AttrEncrypted::KEKProvider::AES.new(OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key),
                     context: 'test'
    end

    let(:klass) { FixedContextTestClass }

    include_examples 'basic functioning'
  end
end
