# frozen_string_literal: true

require 'spec_helper'
require 'teak/attr_encrypted/testing'
require 'teak/attr_encrypted/kek_provider/aes'
require 'securerandom'

RSpec.describe Teak::AttrEncrypted::Testing do
  let(:key) { OpenSSL::Cipher.new('aes-256-gcm').encrypt.random_key }
  let(:provider) { Teak::AttrEncrypted::KEKProvider::AES.new(key) }
  let(:plaintext) { SecureRandom.hex }

  let(:klass) do
    kek = provider
    Class.new do
      include Teak::AttrEncrypted

      def initialize(ctx = nil)
        @ctx = ctx
      end

      attr_accessor :secret_enc

      attr_accessor :ctx

      attr_encrypted :secret, kek_provider: kek, context: :ctx
    end
  end

  after { Teak::AttrEncrypted::Testing.reset! } # rubocop:disable RSpec/DescribedClass

  describe '.allow_encryption_contexts' do
    it 'allows listed contexts' do
      context_value = 'allowed_ctx'
      instance = klass.new({ type: context_value })

      described_class.allow_encryption_contexts(context_value)

      instance.secret = plaintext
      expect(instance.secret).to eq plaintext
    end

    it 'denies unlisted contexts' do
      instance = klass.new({ type: 'other_ctx' })

      described_class.allow_encryption_contexts('allowed_ctx')

      expect { instance.secret = plaintext }.to raise_error(described_class::ContextNotAllowed)
    end

    it 'denies on read when context is not allowed' do
      context_value = { type: 'was_allowed' }
      instance = klass.new({ type: context_value })

      described_class.allow_encryption_contexts(context_value)
      instance.secret = plaintext

      described_class.allow_encryption_contexts('something_else')
      expect { instance.secret }.to raise_error(described_class::ContextNotAllowed)
    end

    it 'allows multiple contexts' do
      described_class.allow_encryption_contexts('ctx_a', 'ctx_b')

      a = klass.new({ type: 'ctx_a' })
      a.secret = plaintext
      expect(a.secret).to eq plaintext
    end

    it 'denies contexts not in the allow list' do
      described_class.allow_encryption_contexts('ctx_a', 'ctx_b')

      expect { klass.new({ type: 'ctx_c' }).secret = plaintext }.to raise_error(described_class::ContextNotAllowed)
    end

    it 'handles nil context as allowed' do
      described_class.allow_encryption_contexts(nil)

      instance = klass.new(nil)
      instance.secret = plaintext
      expect(instance.secret).to eq plaintext
    end

    it 'denies non-nil contexts when only nil is allowed' do
      described_class.allow_encryption_contexts(nil)

      expect { klass.new({ type: 'some_ctx' }).secret = plaintext }.to raise_error(described_class::ContextNotAllowed)
    end
  end

  describe '.reset!' do
    it 'clears all context restrictions' do
      described_class.allow_encryption_contexts('only_this')
      described_class.reset!

      instance = klass.new({ type: 'anything' })
      instance.secret = plaintext
      expect(instance.secret).to eq plaintext
    end
  end

  describe 'with no restrictions configured' do
    it 'allows all contexts' do
      instance = klass.new({ type: 'any_context' })
      instance.secret = plaintext
      expect(instance.secret).to eq plaintext
    end
  end

  describe Teak::AttrEncrypted::Testing::RSpecHelpers do # rubocop:disable RSpec/DescribedClass
    include Teak::AttrEncrypted::Testing::RSpecHelpers # rubocop:disable RSpec/DescribedClass

    it 'delegates allow_encryption_contexts' do
      allow_encryption_contexts('my_ctx')

      instance = klass.new({ type: 'my_ctx' })
      instance.secret = plaintext
      expect(instance.secret).to eq plaintext
    end

    it 'blocks disallowed contexts via allow helper' do
      allow_encryption_contexts('my_ctx')

      expect { klass.new({ type: 'other' }).secret = plaintext }.to raise_error(Teak::AttrEncrypted::Testing::ContextNotAllowed)
    end
  end
end
