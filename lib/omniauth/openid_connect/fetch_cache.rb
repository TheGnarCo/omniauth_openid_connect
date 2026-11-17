# frozen_string_literal: true

module OmniAuth
  module OpenIDConnect
    # Gnar: process-wide cache for what the identity provider serves over HTTP (discovery document, key set).
    #
    # One fetch per key at a time: callers that arrive while a fetch runs wait for it and use its result, whether it
    # worked or failed. A failed fetch is remembered for negative_ttl seconds, so the next callers fail at once
    # instead of each waiting for its own timeout. An expired value is served for up to stale_ttl more seconds when
    # its refresh fails, and each such use is logged at ERROR.
    class FetchCache
      # Raised instead of the original error. The message names the kind and the error class, never response text.
      class FetchFailed < Error
        attr_reader :kind

        def initialize(kind, message)
          super(message)
          @kind = kind
        end
      end

      Entry = Struct.new(:value, :fetched_at, :failed_until, :failure_class)

      def initialize(clock: nil)
        self.clock = clock
        @entries = {}
        @locks = {}
        @guard = Mutex.new
      end

      # A callable returning monotonic seconds; nil restores the process clock.
      def clock=(clock)
        @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      end

      def clear!
        @guard.synchronize { @entries.clear }
      end

      # key is [kind, ...]. replace is a value the caller found unusable (a key set without the needed kid): the
      # entry is refreshed unless another caller already replaced that value.
      def fetch(key, ttl:, negative_ttl:, stale_ttl:, replace: nil, &block)
        entry = read(key)
        return entry.value if usable?(entry, ttl, replace)

        lock_for(key).synchronize do
          entry = read(key)
          return entry.value if usable?(entry, ttl, replace)
          return stale_or_raise(key, entry, ttl, stale_ttl) if entry&.failed_until && now < entry.failed_until

          load_entry(key, entry, ttl, negative_ttl, stale_ttl, &block)
        end
      end

      private

      def now
        @clock.call
      end

      def read(key)
        @guard.synchronize { @entries[key] }
      end

      def write(key, entry)
        @guard.synchronize { @entries[key] = entry }
      end

      def usable?(entry, ttl, replace)
        entry&.value && now - entry.fetched_at < ttl && !(replace && entry.value.equal?(replace))
      end

      def lock_for(key)
        @guard.synchronize { @locks[key] ||= Mutex.new }
      end

      def load_entry(key, entry, ttl, negative_ttl, stale_ttl)
        value = yield
        write(key, Entry.new(value, now, nil, nil))
        value
      rescue StandardError => e
        failed = write(key, Entry.new(entry&.value, entry&.fetched_at, now + negative_ttl, e.class.name))
        stale_or_raise(key, failed, ttl, stale_ttl)
      end

      def stale_or_raise(key, entry, ttl, stale_ttl)
        kind = key.first
        if entry.value && now - entry.fetched_at < ttl + stale_ttl
          OmniAuth.logger.error("openid_connect cache: serving stale #{kind} (age #{(now - entry.fetched_at).round}s, " \
                                "refresh failed: #{entry.failure_class})")
          return entry.value
        end

        raise FetchFailed.new(kind, "#{kind} fetch failed (#{entry.failure_class}); not retried for " \
                                    "#{(entry.failed_until - now).ceil}s")
      end
    end
  end
end
