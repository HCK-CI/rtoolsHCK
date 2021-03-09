# frozen_string_literal: true

require_relative 'exceptions'
require 'winrm'
require 'winrm-fs'

# rubocop:disable Metrics/ClassLength

# server class
class Server
  def initialize(init_opts)
    @log_to_stdout = init_opts[:log_to_stdout]
    @stdout_logger = Logger.new($stdout) if @log_to_stdout
    @logger = init_opts[:logger]
    load_instance_variables(init_opts)
    logger('debug', 'initialize/server') { "on port #{@port}" }
    check_script_file
    load_toolshck_server
  rescue StandardError
    close
    raise
  end

  private

  def logger(level, progname = nil, &block)
    @stdout_logger.public_send(level, progname, &block) if @log_to_stdout
    @logger&.public_send(level, progname, &block)
  end

  def load_instance_variables(init_opts)
    @winrm_ps = init_opts[:connection].shell(:powershell)
    @winrm_fs = WinRM::FS::FileManager.new(init_opts[:connection])
    @port = init_opts[:port]
    @connection_timeout = init_opts[:connection_timeout]
    @outp_dir = init_opts[:outp_dir]
    @l_script_file = init_opts[:l_script_file]
    @r_script_file = init_opts[:r_script_file]
  end

  def check_script_file
    logger('debug', 'initialize/server') { 'checking sctipt file on remote' }
    if !@l_script_file.nil? then deploy_script_file
    elsif !@winrm_fs.exists?(@r_script_file)
      raise ServerError.new('initialize/server'),
            'toolsHCK.ps1 script was not found on remote.'
    end
    logger('debug', 'initialize/server') { 'checked' }
  end

  def deploy_script_file
    logger('debug', 'initialize/server') { 'deploying script file on remote' }
    unless File.file?(@l_script_file)
      raise ServerError.new('initialize/server'),
            "can't find the l_script_file specified."
    end
    @winrm_fs.delete(@r_script_file)
    @winrm_fs.upload(File.expand_path(@l_script_file), @r_script_file)
    logger('debug', 'initialize/server') { 'deployed' }
  end

  def load_toolshck_server
    logger('debug', 'initialize/server') do
      "loading server to listen on port #{@port}"
    end
    @log_r_path = run_server
    run_log_fetcher
    logger('debug', 'initialize/server') { 'loaded' }
  end

  def run_server
    tmp_r_path = "C:\\#{Time.now.strftime('%d-%m-%Y_%H_%M_%S')}_toolsHCK.log"
    run_thread = Thread.new do
      run("$Process = #{process_script(tmp_r_path)}")
      check_log_file_exist_cmd = "[System.IO.File]::Exists('#{tmp_r_path}')"
      until run(check_log_file_exist_cmd).strip.eql?('True'); end
    end

    return tmp_r_path unless run_thread.join(@connection_timeout).nil?

    run_thread.exit
    e_message = 'waiting for the server to run timed out'
    raise ServerError.new('initialize/server'), e_message
  end

  def run(cmd, unchecked: false)
    run_output = @winrm_ps.run(cmd)
    return run_output.stdout if unchecked || run_output.exitcode.zero?

    raise WinrmPSRunError.new('winrm/run'), "Running '#{cmd}' failed"\
      "#{run_output.stderr.empty? ? '' : " with: #{run_output.stderr}"}"
  end

  def process_script(tmp_r_path)
    'Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass", "-File '\
    "#{@r_script_file}\", \"-server -timeout #{@connection_timeout} -port "\
    "#{@port}\" -RedirectStandardOutput #{tmp_r_path} -PassThru -NoNewWindow"
  end

  # log fetcher sleep in seconds (polling rate)
  LOG_FETCHER_SLEEP = 2

  def run_log_fetcher
    @log_fetcher = Thread.new do
      while sleep LOG_FETCHER_SLEEP
        break if @log_fetcher.thread_variable_get(:close)

        fetch_log
      end
    end
  end

  def fetch_log
    return if @outp_dir.nil?

    log_l_path = @outp_dir + "/#{guest_basename(@log_r_path)}"
    FileUtils.touch(log_l_path)

    to_append = r_sub_l_content(log_l_path)

    return if to_append.empty?

    File.open(log_l_path, 'a') do |file|
      file.print(to_append)
    end
  end

  def guest_basename(path)
    path.nil? ? nil : path.split('\\').last
  end

  def r_sub_l_content(log_l_path)
    run("$rContent = Get-Content #{@log_r_path} -ReadCount 1024")
    return '' if run('$rContent -eq $Null').strip.eql?('True')

    from = File.open(log_l_path, 'r') { |l_content| l_content.readlines.size }
    return '' if run('$rContent.Length').strip.to_i == from

    run("$rContent[#{from}..($rContent.Length-1)]")
  ensure
    run('[System.GC]::Collect()')
  end

  public

  def close
    logger('debug', 'close/server') { 'closing server' }
    run('Stop-Process -Id $Process.Id -ErrorAction Ignore -Force', true)
    return unless @log_r_path && @log_fetcher

    @log_fetcher.thread_variable_set(:close, true)
    @log_fetcher.join
    fetch_log
  ensure
    logger('debug', 'close/server') { 'closed' }
    @winrm_ps&.close
  end
end

# rubocop:enable Metrics/ClassLength
