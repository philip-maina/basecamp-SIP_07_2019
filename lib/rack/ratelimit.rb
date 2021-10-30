require 'logger'
require 'time'

module Rack
  # = Ratelimit
  #
  # * Run multiple rate limiters in a single app
  # * Scope each rate limit to certain requests: API, files, GET vs POST, etc.
  # * Apply each rate limit by request characteristics: IP, subdomain, OAuth2 token, etc.
  # * Flexible time window to limit burst traffic vs hourly or daily traffic:
  #     100 requests per 10 sec, 500 req/minute, 10000 req/hour, etc.
  # * Fast, low-overhead implementation using counters per time window:
  #     timeslice = window * ceiling(current time / window)
  #     store.incr(timeslice)
  # * Choose to ban a client for a given time interval, for all requests, if rate limit is exceeded.
  class Ratelimit
    # Takes a block that classifies requests for rate limiting with the possibility
    # of banning all requests that exceed the specified rate limit. Given a
    # Rack env, return a string such as IP address, API token, etc. If the
    # block returns nil, the request won't be rate-limited. If a block is
    # not given, all requests get the same limits.
    #
    # Required configuration:
    #   rate: an array of [max requests, period in seconds]: [500, 5.minutes]
    # and one of
    #   cache: a Dalli::Client instance
    #   redis: a Redis instance
    #   counter [DEPRECATED (use persister instead)]: Your own custom counter. 
    #     Must respond to
    #       `#increment(classification_string, end_of_time_window_epoch_timestamp)`
    #       and return the counter value after increment.
    #   persister: Your own custom persister. 
    #     Must respond to 
    #       `#increment(classification_string, end_of_time_window_epoch_timestamp)`
    #       and return the counter value after increment.
    #     If ban_duration is set, must also respond to
    #       `#ban(classification_string)` - add classification_string to list of banned classification
    #        strings; return a truthy value.
    #       `#banned?(classification_string)` check if classification_string is in
    #       list of banned classification_strings; return a boolean value.
    #
    # Optional configuration:
    #   name: name of the rate limiter. Defaults to 'HTTP'. Used in messages.
    #   ban_duration: period in seconds a client should be banned when rate limit is exceeded
    #   status: HTTP response code. Defaults to 429.
    #   conditions: array of procs that take a rack env, all of which must
    #     return true to rate-limit the request.
    #   exceptions: array of procs that take a rack env, any of which may
    #     return true to exclude the request from rate limiting.
    #   logger: responds to #info(message). If provided, the rate limiter
    #     logs the first request that hits the rate limit, but none of the
    #     subsequently blocked requests.
    #   error_message: the message returned in the response body when the rate
    #     limit is exceeded. Defaults to "<name> rate limit exceeded. Please
    #     wait %d seconds then retry your request." The number of seconds
    #     until the end of the rate-limiting window is interpolated into the
    #     message string, but the %d placeholder is optional if you wish to
    #     omit it.
    #
    # Example:
    #
    # Rate-limit bursts of POST/PUT/DELETE by IP address, return 503:
    #   use(Rack::Ratelimit, name: 'POST',
    #     exceptions: ->(env) { env['REQUEST_METHOD'] == 'GET' },
    #     rate:   [50, 10.seconds],
    #     status: 503,
    #     cache:  Dalli::Client.new,
    #     logger: Rails.logger) { |env| Rack::Request.new(env).ip }
    #
    # Rate-limit API traffic by user (set by Rack::Auth::Basic):
    #   use(Rack::Ratelimit, name: 'API',
    #     conditions: ->(env) { env['REMOTE_USER'] },
    #     rate:   [1000, 1.hour],
    #     ban_duration: 24.hours,
    #     redis:  Redis.new(ratelimit_redis_config),
    #     logger: Rails.logger) { |env| env['REMOTE_USER'] }
    def initialize(app, options, &classifier)
      @app, @classifier = app, classifier
      @classifier ||= lambda { |env| :request }

      @name = options.fetch(:name, 'HTTP')
      @max, @period = options.fetch(:rate)
      @status = options.fetch(:status, 429)

      @logger        = options[:logger]
      @error_message = options.fetch(:error_message, "#{@name} rate limit exceeded. Please wait %d seconds then retry your request.")

      @ban_duration = options.fetch(:ban_duration, 0)
      @persister    = get_persister(options)
      
      @conditions = Array(options[:conditions])
      @exceptions = Array(options[:exceptions])
    end

    # Add a condition that must be met before applying the rate limit.
    # Pass a block or a proc argument that takes a Rack env and returns
    # true if the request should be limited.
    def condition(predicate = nil, &block)
      @conditions << predicate if predicate
      @conditions << block if block_given?
    end

    # Add an exception that excludes requests from the rate limit.
    # Pass a block or a proc argument that takes a Rack env and returns
    # true if the request should be excluded from rate limiting.
    def exception(predicate = nil, &block)
      @exceptions << predicate if predicate
      @exceptions << block if block_given?
    end

    def get_persister(options)
      return get_counter(options[:counter])           if options[:counter]
      return get_memcached_persister(options[:cache]) if options[:cache]
      return get_redis_persister(options[:redis])     if options[:redis] 

      raise ArgumentError, '`:persister`,`:cache`,`:redis` or `:counter` is required' unless persister = options[:persister]
      raise ArgumentError, 'Persister must respond to #increment' unless persister.respond_to?(:increment)
      raise ArgumentError, 'Persister must respond to #ban'       unless persister.respond_to?(:ban)
      raise ArgumentError, 'Persister must respond to #banned?'   unless persister.respond_to?(:banned?)

      persister
    end

    def get_counter(counter)
      @logger.warn 'DEPRECATION WARNING: `:counter` is deprecated and will be removed in future releases (use `:persister` instead)'
      raise ArgumentError, '`:counter` cannot be used with `:ban_duration`. Please prefer `:persister`' if bannable?
      raise ArgumentError, 'Counter must respond to #increment' unless counter.respond_to?(:increment)
      counter
    end

    def get_memcached_persister(cache)
      Persister::Memcached.new(cache, @name, @period, @ban_duration)
    end

    def get_redis_persister(redis)
      Persister::Redis.new(redis, @name, @period, @ban_duration)
    end

    def bannable?
      @ban_duration > 0
    end

    def ban_response
      [403, { 'Content-Type' => 'text/plain' }, ["Forbidden Access! \nYou don’t have permission to access this resource"]]
    end

    # Apply the rate limiter if none of the exceptions apply and all the
    # conditions are met.
    def apply_rate_limit?(env)
      @exceptions.none? { |e| e.call(env) } && @conditions.all? { |c| c.call(env) }
    end

    # Give subclasses an opportunity to specialize classification.
    def classify(env)
      @classifier.call env
    end

    # Handle a Rack request:
    #   * Check whether the rate limit applies to the request.
    #   * Classify the request by IP, API token, etc.
    #   * Calculate the end of the current time window.
    #   * Increment the counter for this classification and time window.
    #   * If count exceeds limit, return a 429 response.
    #   * If it's the first request that exceeds the limit, log it.
    #   * If the count doesn't exceed the limit, pass through the request.
    def call(env)
      classification = classify(env)
      
      return ban_response   if bannable? && classification && @persister.banned?(classification)
      return @app.call(env) unless apply_rate_limit?(env) && classification
      
      # Accept an optional start-of-request timestamp from the Rack env for
      # upstream timing and for testing.
      now = env.fetch('ratelimit.timestamp', Time.now).to_f

      # Increment the request counter.
      epoch     = ratelimit_epoch(now)
      count     = @persister.increment(classification, epoch)
      remaining = @max - count

      # If exceeded, return a 429 Rate Limit Exceeded response.
      if remaining < 0
        # Ban Client (if indicated)
        if bannable?
          @persister.ban(classification)
          return ban_response
        end
    
        # Only log the first hit that exceeds the limit.
        if @logger && remaining == -1
          @logger.info '%s: %s exceeded %d request limit for %s' % [@name, classification, @max, format_epoch(epoch)]
        end

        retry_after = seconds_until_epoch(epoch)

        [ @status,
          { 'X-Ratelimit' => ratelimit_json(remaining, epoch),
            'Retry-After' => retry_after.to_s },
          [ @error_message % retry_after ] ]

      # Otherwise, pass through then add some informational headers.
      else
        @app.call(env).tap do |status, headers, body|
          amend_headers headers, 'X-Ratelimit', ratelimit_json(remaining, epoch)
        end
      end 
    end

    private
      # Calculate the end of the current rate-limiting window.
      def ratelimit_epoch(timestamp)
        @period * (timestamp / @period).ceil
      end

      def ratelimit_json(remaining, epoch)
        %({"name":"#{@name}","period":#{@period},"limit":#{@max},"remaining":#{remaining < 0 ? 0 : remaining},"until":"#{format_epoch(epoch)}"})
      end

      def format_epoch(epoch)
        Time.at(epoch).utc.xmlschema
      end

      # Clamp negative durations in case we're in a new rate-limiting window.
      def seconds_until_epoch(epoch)
        sec = (epoch - Time.now.to_f).ceil
        sec = 0 if sec < 0
        sec
      end

      def amend_headers(headers, name, value)
        headers[name] = [headers[name], value].compact.join("\n")
      end

    class Persister
      attr_reader :client, :name, :period, :ban_duration
                
      def initialize(client, name, period, ban_duration)
        @client, @name, @period, @ban_duration = client, name, period, ban_duration
      end

      def banned?(classification)
        !client.get(ban_key(classification)).nil?
      end

      private
        def ban_key(classification)
          'rack-ratelimit/%s/%s' % [name, classification]
        end

        def increment_key(classification, epoch)
          'rack-ratelimit/%s/%s/%i' % [name, classification, epoch]
        end
    end

    class Persister::Redis < Persister
      def ban(classification)
        key = ban_key(classification)

        client.multi do
          client.set(key, 1)
          client.expire(key, ban_duration)
        end
      rescue ::Redis::BaseError
        0
      end

      # Increment the request counter and return the current count.
      def increment(classification, epoch)
        key = increment_key(classification, epoch)

        # Returns [count, expire_ok] response for each multi command.
        # Return the first, the count.
        client.multi do |redis|
          client.incr key
          client.expire key, period
        end.first
      rescue ::Redis::BaseError
        0
      end
    end

    class Persister::Memcached < Persister
      def ban(classification)
        client.set(ban_key(classification), 1, ban_duration)
      rescue ::Dalli::DalliError
        0
      end

      def increment(classification, epoch)
        key = increment_key(classification, epoch)

        # Try to increment the counter if it's present.
        if count = client.incr(key, 1)
          count.to_i

        # If not, add the counter and set expiry.
        elsif client.add(key, 1, period, :raw => true)
          1

        # If adding failed, someone else added it concurrently. Increment.
        else
          client.incr(key, 1).to_i
        end
      rescue ::Dalli::DalliError
        0
      end
    end
  end
end
