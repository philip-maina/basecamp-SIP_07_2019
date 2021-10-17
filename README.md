Rack::Ratelimit
===============

* Run multiple rate limiters in a single app
* Scope each rate limit to certain requests: API, files, GET vs POST, etc.
* Apply each rate limit by request characteristics: IP, subdomain, OAuth2 token, etc.
* Flexible time window to limit burst traffic vs hourly or daily traffic:
    100 requests per 10 sec, 500 req/minute, 10000 req/hour, etc.
* Fast, low-overhead implementation in memcache using counters for discrete timeslices:
    timeslice = window * ceiling(current time / window)
    memcache.incr(counter for timeslice)
* Choose to ban a client for a given time interval, for all requests, if rate limit is exceeded.


Configuration
-------------

Takes a block that classifies requests for rate limiting with the possibility
of banning all requests that exceed the specified rate limit. Given a
Rack env, return a string such as IP address, API token, etc. If the
block returns nil, the request won't be rate-limited. If a block is
not given, all requests get the same limits.

Required configuration:
* rate: an array of [max requests, period in seconds]: [500, 5.minutes]

and one of
* cache: a Dalli::Client instance
* redis: a Redis instance
* counter: Your own custom counter.  
  Must respond to 
    * `#increment(classification_string, end_of_time_window_timestamp)` and return the counter value after increment.

Optional configuration:
* ban_duration: period in seconds a client should be banned when rate limit is exceeded.
* banner: Your own custom banner. **This is required when counter configuration option 
  is provided**.  
  Must respond to
    * `#ban(classification_string)` and return a truthy value after adding the client to the list of banned clients.
    * `#banned?(classification_string)` and return a boolean value indicating whether a particular client has been banned from all requests.
* name: name of the rate limiter. Defaults to 'HTTP'. Used in messages.
* conditions: array of procs that take a rack env, all of which must
    return true to rate-limit the request.
* exceptions: array of procs that take a rack env, any of which may
    return true to exclude the request from rate limiting.
* logger: responds to #info(message). If provided, the rate limiter
    logs the first request that hits the rate limit, but none of the
    subsequently blocked requests.
* error_message: the message returned in the response body when the rate
    limit is exceeded. Defaults to "<name> rate limit exceeded. Please
    wait <period> seconds then retry your request."


Examples
--------

Rate-limit bursts of POST/PUT/DELETE requests by IP address

    use(Rack::Ratelimit, name: 'POST',
      exceptions: ->(env) { env['REQUEST_METHOD'] == 'GET' },
      rate:   [50, 10.seconds],
      cache:  Dalli::Client.new,
      logger: Rails.logger) { |env| Rack::Request.new(env).ip }

Rate-limit API traffic by user (set by Rack::Auth::Basic)

    use(Rack::Ratelimit, name: 'API',
      conditions: ->(env) { env['REMOTE_USER'] },
      rate:   [1000, 1.hour],
      redis:  Redis.new(ratelimit_redis_config),
      logger: Rails.logger) { |env| env['REMOTE_USER'] }

Ban all requests by IP address when rate limit is exceeded
    
    use(Rack::Ratelimit, name: 'login_brute_force',
      conditions: ->(env) { env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] =~ /\A\/sessions/ },
      rate: [10, 5.minutes],
      ban_duration: 24.hours,
      cache:  Dalli::Client.new,
      logger: Rails.logger) { |env| Rack::Request.new(env).ip }

That is: if we see over 10 POST requests to /sessions in 5 minutes, we want that IP address to be banned completely for 24 hours, for ALL requests.
