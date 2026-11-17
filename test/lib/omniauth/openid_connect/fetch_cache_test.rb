# frozen_string_literal: true

require 'logger'
require 'stringio'
require_relative '../../../test_helper'

module OmniAuth
  module OpenIDConnect
    class FetchCacheTest < Minitest::Test
      TTLS = { ttl: 60, negative_ttl: 10, stale_ttl: 30 }.freeze

      def setup
        @now = 0.0
        @cache = FetchCache.new(clock: -> { @now })
        @log = StringIO.new
        @saved_logger = OmniAuth.config.logger
        OmniAuth.config.logger = Logger.new(@log)
      end

      def teardown
        OmniAuth.config.logger = @saved_logger
      end

      def fetch(key = %i[discovery url], **opts, &block)
        @cache.fetch(key, **TTLS.merge(opts), &block)
      end

      def test_reuses_a_value_inside_the_ttl_and_refetches_after
        loads = 0
        2.times { fetch { loads += 1 } }
        assert_equal 1, loads
        @now += 61
        fetch { loads += 1 }
        assert_equal 2, loads
      end

      def test_concurrent_callers_share_one_fetch
        loads = Queue.new
        threads = Array.new(5) do
          Thread.new do
            fetch do
              loads << 1
              sleep 0.2
              :value
            end
          end
        end
        assert_equal [:value] * 5, threads.map(&:value)
        assert_equal 1, loads.size
      end

      def test_a_failure_is_remembered_for_negative_ttl_without_provider_text
        loads = 0
        2.times do
          error = assert_raises(FetchCache::FetchFailed) { fetch { (loads += 1) && raise('provider said <b>no</b>') } }
          refute_includes error.message, 'provider said'
          assert_equal :discovery, error.kind
        end
        assert_equal 1, loads
        @now += 11
        assert_equal(:ok, fetch { :ok })
      end

      def test_replace_refreshes_only_the_value_the_caller_found_unusable
        first = fetch { 'v1' }
        assert_equal 'v1', fetch(replace: 'other') { 'v2' }
        assert_equal 'v2', fetch(replace: first) { 'v2' }
      end

      def test_forced_refreshes_are_limited_to_one_per_min_replace_interval
        loads = 0
        value = fetch { loads += 1 }
        2.times { value = fetch(replace: value, min_replace_interval: 60) { loads += 1 } }
        assert_equal 2, loads
        @now += 61
        fetch(replace: value, min_replace_interval: 60) { loads += 1 }
        assert_equal 3, loads
      end

      def test_stale_value_is_served_inside_the_stale_window_and_logged
        fetch { 'v1' }
        @now += 70
        assert_equal('v1', fetch { raise 'down' })
        assert_match(/ERROR.*serving stale discovery/, @log.string)
        @now += 30
        assert_raises(FetchCache::FetchFailed) { fetch { raise 'down' } }
      end
    end
  end
end
