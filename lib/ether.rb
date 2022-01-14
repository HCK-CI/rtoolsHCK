# frozen_string_literal: true

require_relative 'exceptions'
require_relative 'server'
require 'socket'

# ether class
class Ether
  def initialize(server_init_opts, init_opts)
    @server_init_opts = server_init_opts
    @log_to_stdout = init_opts[:log_to_stdout]
    @stdout_logger = Logger.new($stdout) if @log_to_stdout
    @logger = init_opts[:logger]
    load_instance_variables(init_opts)
    load_server
    logger('debug', 'initialize/ether') { "to #{@addr}:#{@port}" }
    load_ether
  rescue StandardError
    close
    raise
  end

  private

  def get_exception_stack(exception)
    exception.backtrace.select { |line| line.include?(File.dirname(__FILE__)) }\
             .join("\n   -- ")
  end

  def log_exception(exception, level)
    eclass = exception.class
    emessage = exception.message
    estack = get_exception_stack(exception)
    if exception.is_a?(RToolsHCKError)
      ewhere = exception.where
      logger(level, ewhere) { "(#{eclass}) #{emessage}\n   -- #{estack}" }
    else
      logger(level, eclass) { "#{emessage}\n   -- #{estack}" }
    end
  end

  def logger(level, progname = nil, &block)
    @stdout_logger.public_send(level, progname, &block) if @log_to_stdout
    @logger&.public_send(level, progname, &block)
  end

  def load_instance_variables(init_opts)
    @addr = init_opts[:addr]
    @port = init_opts[:port]
    @timeout = init_opts[:timeout]
    @connection_timeout = init_opts[:connection_timeout]
  end

  def load_server
    logger('debug', 'initialize/ether') { 'server is not running' } if @toolshck_server.nil?
    @toolshck_server ||= Server.new(@server_init_opts)
  end

  def load_ether
    logger('debug', 'initialize/ether') { 'waiting for client acceptance' }
    wait_for_client_acceptance
    logger('debug', 'initialize/ether') { 'connected' }
  end

  def wait_for_client_acceptance
    @ether = connect

    unless fetch_output_with_timeout(@connection_timeout).eql?('START')
      e_message = 'something went wrong, didn\'t receive (START)'
      raise EtherError.new('initialize/ether'), e_message
    end
  rescue Timeout::Error
    e_message = 'waiting for the client acceptance timed out'
    raise EtherError.new('initialize/ether'), e_message
  end

  def connect
    TCPSocket.new(@addr, @port)
  rescue Errno::ECONNREFUSED
    retry
  end

  def fetch_output_with_timeout(timeout)
    Timeout.timeout(timeout) do
      until @ether.ready?; end

      length = @ether.readline.rstrip.to_i

      fetch(length)
    end
  rescue IO::WaitReadable, Errno::ECONNRESET, EOFError, Errno::EPIPE => e
    raise EtherError.new('ether'), "[#{e.class}] #{e.message}", e.backtrace
  end

  # ether buffer size
  ETHER_BUFFER_SIZE = 1024

  def fetch(length)
    data = ''
    while data.length != length
      until @ether.ready?; end

      read_length = [ETHER_BUFFER_SIZE, length - data.length].min
      data += @ether.read_nonblock(read_length)
    end
    data
  end

  def unload_server
    @toolshck_server&.close
  rescue StandardError => e
    log_exception(e, 'debug')
  end

  # ether exit timeout
  ETHER_EXIT_TIMEOUT = 5

  public

  def close
    logger('debug', 'close/ether') { 'closing ether' }
    if @ether && !cmd('exit', ETHER_EXIT_TIMEOUT).eql?('END')
      e_message = 'closing failed'
      raise EtherError.new('close/ether'), e_message
    end
  ensure
    logger('debug', 'close/ether') { 'closed' }
    @ether&.close
    unload_server
  end

  def cmd(cmd, timeout = @timeout)
    flush

    @ether.puts(cmd)

    fetch_output_with_timeout(timeout)
  rescue Timeout::Error
    raise EtherError.new('cmd/ether'), "cmd (#{cmd}) timed out"
  end

  private

  def flush
    flushed = ''
    loop { flushed += @ether.read_nonblock(ETHER_BUFFER_SIZE) }
  rescue IO::WaitReadable, Errno::ECONNRESET, EOFError, Errno::EPIPE
    return if flushed.empty?

    logger('debug', 'flush/ether') { "flushed data:\n#{flushed}" }
  end
end
