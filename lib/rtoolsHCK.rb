#!/usr/bin/env ruby

require 'net/telnet'
require 'securerandom'
require 'winrm'
require 'winrm-fs'
require 'logger'
require 'json'
require 'tempfile'

# rubocop:disable Metrics/ClassLength, Metrics/ParameterLists

# == Description
#
# A ruby class the resembles tool set for HCK\HLK with various purposes which
# covers several actions as explained in the list if actions below.
#
# == Actions list
#
# +list_pools+::                 Lists the pools info.
#
# +create_pool+::                Creates a pool.
#
# +delete_pool+::                Deletes a pool.
#
# +move_machine+::               Moves a machine from one pool to another.
#
# +set_machine_state+::          Sets the state of a machine to Ready or
#                                NotReady.
#
# +delete_machine+::             Deletes a machine
#
# +list_machine_targets+::       Lists the target devices of a machine that are
#                                available to be tested.
#
# +list_projects+::              Lists the projects info.
#
# +create_project+::             Creates a project.
#
# +delete_project+::             Deletes a project.
#
# +create_project_target+::      Creates a project's target.
#
# +delete_project_target+::      Deletes a project's target.
#
# +list_tests+::                 Lists a project target's tests.
#
# +get_test_info+::              Gets a project target's test info.
#
# +queue_test+::                 Queue's a test, use get_test_results to get the
#                                results.
#
# +update_filters+::             Updates the HCK\HLK controller's filters.
#
# +apply_project_filters+::      Applies the filters on a project's test
#                                results.
#
# +apply_test_result_filters+::  Applies the filters on a test result.
#
# +list_test_results+::          Lists a test results info.
#
# +zip_test_result_logs+::       Zipps a test result's log and fetches the zip.
#
# +create_project_package+::     Creates a project's package.
class RToolsHCK
  WINRM_OPERATION_TIMEOUT = 9_999
  WINRM_RECIEVE_TIMEOUT = 99_999

  private

  # A custom RToolsHCK error exception
  class RToolsHCKError < StandardError
    # Custom addition to the exception backtrace, (better logging)
    attr_reader :where

    # Initialization of the custom exception
    def initialize(where)
      @where = where
    end
  end

  # A custom RToolsHCK connection error exception
  class RToolsHCKConnectionError < RToolsHCKError; end

  # A custom RToolsHCK action error exception
  class RToolsHCKActionError < RToolsHCKError; end

  # A custom Winrm powershell run error exception
  class WinrmPSRunError < RToolsHCKActionError; end

  def handle_exceptions
    yield
  rescue StandardError => e
    log_exception(e)
    raise e
  end

  def get_exception_stack(exception)
    exception.backtrace.select { |line| line.include?(File.dirname(__FILE__)) }\
             .join("\n   -- ")
  end

  def log_exception(exception)
    eclass = exception.class
    emessage = exception.message
    estack = get_exception_stack(exception)
    if exception.is_a?(RToolsHCKError)
      ewhere = exception.where
      logger('error', ewhere) { "(#{eclass}) #{emessage}\n   -- #{estack}" }
    else
      logger('error', eclass) { "#{emessage}\n   -- #{estack}" }
    end
  end

  def logger(level, progname = nil, &block)
    @stdout_logger.public_send(level, progname, &block) if @log_to_stdout
    @logger.public_send(level, progname, &block) if @logger
  end

  # A little workaround of a net-telnet bug
  #
  class Telnet < Net::Telnet
    #-----------------------------------------#
    #--Changes to the existing Telnet class.--#
    #-----------------------------------------#
    def print(string)
      string = string.gsub(/#{IAC}/no, IAC + IAC) if @options['Telnetmode']
      return write(string) if @options['Binmode']

      if @telnet_option['BINARY'] && @telnet_option['SGA']
        write(string.gsub(/\n/n, CR))
      else
        write(string.gsub(/\n/n, EOL))
      end
    end
    #-----------------------------------------#
    #--End of changes.------------------------#
    #-----------------------------------------#
  end

  public

  # == Description
  #
  # Initializes new object of type RToolsHCK to be used by establishing a
  # Telnet and a Tftp connection with the guest machine.
  #
  # == Params:
  #
  # +init_opts+::    Hash that has various initialize options to configure upon
  #                  initializing a RtoolsHCK object:
  #   :addr          - Controller machine's IP address
  #                    (default: 127.0.0.1)
  #   :user          - The user name to use in order to connect via winrm to the
  #                    guest
  #                    (default: Administrator)
  #   :pass          - The password of the user name specified
  #                    (default: PASSWORD)
  #   :winrm_ports   - The clients winrm connection ports as a hash
  #                    (example: { 'Client' => port, ... })
  #                    (default: { 'Cl1' => 4001, 'Cl2' => 4002 }
  #   :json          - JSON format the output of the action methods
  #                    (default: true)
  #   :timeout       - The action's timeout in seconds
  #                    (default: 60)
  #   :log_to_stdout - Log to STDOUT switch
  #                    (default: false)
  #   :logger        - The ruby logger object for logging
  #                    (default: disabled)
  #   :outp_dir      - The path of the directory to fetch the output files to on
  #                    the local machine
  #                    (default: disabled)
  #   :script_file   - The toolsHCK.ps1 file path on local machine
  #                    (default: disabled)
  #
  def initialize(init_opts)
    init_opts = validate_init_opts(init_opts)

    @log_to_stdout = init_opts[:log_to_stdout]
    @stdout_logger = Logger.new(STDOUT) if @log_to_stdout
    @logger = init_opts[:logger]
    handle_exceptions do
      do_initialize(init_opts)
    end
  end

  private

  # init_opts initialization defaults
  INIT_OPTS_DEFAULTS = {
    addr: '127.0.0.1',
    user: 'Administrator',
    pass: 'PASSWORD',
    winrm_ports: { 'Cl1' => 4001, 'Cl2' => 4002 },
    json: true,
    timeout: 60,
    logger: false,
    log_to_stdout: false,
    outp_dir: nil,
    script_file: nil
  }.freeze

  def validate_init_opts(init_opts)
    (init_opts.keys - INIT_OPTS_DEFAULTS.keys).each do |option|
      raise RToolsHCKError.new('initialize'),
            "Undefined initialization option #{option.inspect}."
    end

    INIT_OPTS_DEFAULTS.merge(init_opts)
  end

  def do_initialize(init_opts)
    load_outp_dir(init_opts[:outp_dir])
    load_instance_variables(init_opts)
    logger('debug', 'initialize') { "#{@user}:#{@pass}@#{@addr}" }
    load_winrm_ps
    load_winrm_fs
    check_guest_tools_hck(init_opts[:script_file])
    load_toolshck
    @closed = false
  end

  def load_outp_dir(outp_dir)
    @outp_dir = nil
    return if outp_dir.nil?

    unless File.directory?(outp_dir)
      raise RToolsHCKError.new('initialize/outp'),
            "can't find the directory outp_dir specefied."
    end
    @outp_dir = File.expand_path(outp_dir)
    logger('debug', 'initialize/outp') { "outp_dir assigned to #{@outp_dir}" }
  end

  def load_instance_variables(init_opts)
    @addr = init_opts[:addr]
    @user = init_opts[:user]
    @pass = init_opts[:pass]
    @winrm_ports = init_opts[:winrm_ports]
    @timeout = init_opts[:timeout]
    @json = init_opts[:json]
  end

  def winrm_options_factory(addr, port, user, pass)
    {
      endpoint: "http://#{addr}:#{port}/wsman",
      operation_timeout: WINRM_OPERATION_TIMEOUT,
      receive_timeout: WINRM_RECIEVE_TIMEOUT,
      transport: :plaintext,
      user: user,
      password: pass,
      basic_auth_only: true
    }
  end

  def do_load_winrm_ps
    options = winrm_options_factory(@addr, 5985, @user, @pass)
    @connection = WinRM::Connection.new(options)
    @winrm_ps = @connection.shell(:powershell)
  end

  def load_winrm_ps
    logger('debug', 'initialize/winrm') { 'loading winrm shell...' }
    do_load_winrm_ps
    check_winrm_ps
    logger('debug', 'initialize/winrm') { 'winrm shell loaded!' }
  end

  def run(cmd)
    run_output = @winrm_ps.run(cmd)
    unless run_output.exitcode.zero?
      raise WinrmPSRunError.new('winrm/run'), "Running '#{cmd}' failed"\
              "#{run_output.stderr.empty? ? '.' : " with #{run_output.stderr}"}"
    end
    run_output.stdout
  end

  def machine_connection(machine)
    listen_port = @winrm_ports[machine]
    options = winrm_options_factory(@addr, listen_port, @user, @pass)
    WinRM::Connection.new(options)
  end

  def machine_run(machine, cmd)
    run_output = machine_connection(machine).shell(:powershell).run(cmd)
    unless run_output.exitcode.zero?
      where = "#{machine}/winrm/run"
      raise WinrmPSRunError.new(where), "Running '#{cmd}' failed"\
              "#{run_output.stderr.empty? ? '.' : " with #{run_output.stderr}"}"
    end
    run_output.stdout
  end

  def check_winrm_ps
    run('date')
  rescue StandardError
    @winrm_ps.close
    raise
  end

  def load_winrm_fs
    logger('debug', 'initialize/winrm') do
      'creating winrm file manager instance'
    end
    @winrm_fs = WinRM::FS::FileManager.new(@connection)
    logger('debug', 'initialize/winrm') do
      'winrm file manager instance created!'
    end
  rescue StandardError
    @winrm_ps.close
    raise
  end

  def do_check_guest_tools_hck(script_file)
    if !script_file.nil? then deploy_tools_hck(script_file)
    elsif !@winrm_fs.exists?('C:\\toolsHCK.ps1')
      raise RToolsHCKError.new('initialize/toolsHCK'),
            'toolsHCK.ps1 script was not found on the guest.'
    end
  end

  def check_guest_tools_hck(script_file)
    logger('debug', 'initialize/toolsHCK') do
      'checking availability on guest...'
    end
    do_check_guest_tools_hck(script_file)
    logger('debug', 'initialize/toolsHCK') { 'availability on guest checked!' }
  rescue StandardError
    @winrm_ps.close
    raise
  end

  def deploy_tools_hck(script_file)
    logger('debug', 'initialize/toolsHCK') { 'deploying toolsHCK on guest...' }
    unless File.file?(script_file)
      raise RToolsHCKError.new('initialize/toolsHCK'),
            "can't find the script_file specified."
    end
    @winrm_fs.delete('C:\\toolsHCK.ps1')
    @winrm_fs.upload(File.expand_path(script_file), 'C:\\toolsHCK.ps1')
    logger('debug', 'initialize/toolsHCK') { 'toolsHCK deployed on guest!' }
  end

  def load_toolshck
    load_toolshck_telnet
    load_toolshck_shell
  rescue StandardError
    @winrm_ps.close
    raise
  end

  # Telnet's prompt match, (regex)
  TELNET_PROMPT_MATCH = /^.:.*>/

  def load_toolshck_telnet
    logger('debug', 'initialize/toolsHCK') { 'loading toolsHCK telnet...' }
    @toolshck_telnet = Telnet.new('Host' => @addr,
                                  'Prompt' => TELNET_PROMPT_MATCH,
                                  'Timeout' => @timeout)
    @toolshck_telnet.login(@user, @pass)
    check_toolshck_telnet
    logger('debug', 'initialize/toolsHCK') { 'toolsHCK telnet loaded!' }
  end

  def check_toolshck_telnet
    if @toolshck_telnet.cmd('cd C:\\').nil?
      raise RToolsHCKError.new('initialize/toolsHCK'),
            'connection with guest not established.'
    end
  rescue StandardError
    @toolshck_telnet.close
    raise
  end

  # toolsHCK telnet shell prompt match, (regex)
  TOOLSHCK_SHELL_PROMPT_MATCH = /^toolsHCK@.*>/

  def load_toolshck_shell
    logger('debug', 'initialize/toolsHCK') { 'loading toolsHCK shell...' }
    @toolshck_telnet.cmd(
      'String' => 'powershell -ExecutionPolicy Bypass -File C:\\toolsHCK.ps1"',
      'Match' => TOOLSHCK_SHELL_PROMPT_MATCH
    )
    logger('debug', 'initialize/toolsHCK') { 'toolsHCK shell loaded!' }
  rescue StandardError
    @toolshck_telnet.close
    raise
  end

  def toolshckcmd(cmd, match = TOOLSHCK_SHELL_PROMPT_MATCH)
    @toolshck_telnet.puts(cmd)
    stream = @toolshck_telnet.waitfor('String' => cmd, 'Match' => match)
    stream.split("\n")[1..stream.split("\n").size - 2].join("\n")
  rescue Net::ReadTimeout, Errno::ECONNRESET, Errno::EPIPE => e
    raise RToolsHCKConnectionError.new('toolsHCK'),
          "[#{e.class}] #{e.message}", e.backtrace
  end

  def guest_basename(path)
    path.nil? ? nil : path.split('\\').last
  end

  def guest_dirname(path)
    n_path = nil
    unless path.nil?
      n_path = path.split('\\').first(path.split('\\').size - 1).join('\\')
    end
    n_path
  end

  def handle_return(stream)
    if @json
      JSON.parse(stream)
    else
      puts(stream)
      stream.include?('WARNING') ? false : true
    end
  end

  def log_action_call(action, binding)
    action_parameters = method(action).parameters.map do |param|
      param_str = "#{param[1]} "
      param_str << if param[0].equal?(:opt)
                     "is #{binding.local_variable_get(param[1]) ? 'on' : 'off'}"
                   else
                     "= #{binding.local_variable_get(param[1])}"
                   end
    end
    logger('debug', "action/#{action}") { action_parameters.join(', ') }
  end

  def handle_action_exceptions(action, &block)
    raise RToolsHCKError.new('action'), 'instance is closed.' if @closed

    log_action_call(action, block.binding)
    handle_exceptions { yield }
  rescue RToolsHCKActionError => e
    if @json
      { 'result' => 'Failure', 'message' => e.message }
    else
      puts "WARNING: #{e.message}"
      false
    end
  end

  public

  attr_accessor :json

  # == Description
  #
  # Lists the pools info.
  #
  def list_pools
    handle_action_exceptions(__method__) do
      cmd_line = ['listpools']
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Creates a pool.
  #
  # == Params:
  #
  # +pool+::         The name of the pool
  def create_pool(pool)
    handle_action_exceptions(__method__) do
      cmd_line = ["createpool '#{pool}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Deletes a pool.
  #
  # == Params:
  #
  # +pool+::         The name of the pool
  def delete_pool(pool)
    handle_action_exceptions(__method__) do
      cmd_line = ["deletepool '#{pool}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Moves a machine from one pool to another.
  #
  # == Params:
  #
  # +machine+::      The name of the machine
  # +from+::         The name of the source pool
  # +to+::           The name of the destination pool
  def move_machine(machine, from, to)
    handle_action_exceptions(__method__) do
      cmd_line = ["movemachine '#{machine}' '#{from}' '#{to}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Sets the state of a machine to Ready or NotReady.
  #
  # == Params:
  #
  # +machine+::      The name of the machine
  # +pool+::         The name of the pool
  # +state+::        The state, Ready or NotReady
  # +timeout+::      The action's timeout in seconds, 60 by deafult
  def set_machine_state(machine, pool, state, timeout = nil)
    timeout ||= 60
    handle_action_exceptions(__method__) do
      cmd_line = ["setmachinestate '#{machine}' '#{pool}' '#{state}'"]
      cmd_line << "-timeout #{timeout}" unless timeout.nil?
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Deletes a machine.
  #
  # == Params:
  #
  # +machine+::      The name of the machine
  # +pool+::         The name of the pool
  def delete_machine(machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = ["deletemachine '#{machine}' '#{pool}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Lists the target devices of a machine that are available to be tested.
  #
  # == Params:
  #
  # +machine+::      The name of the machine
  # +pool+::         The name of the pool
  def list_machine_targets(machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = ["listmachinetargets '#{machine}' '#{pool}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Lists the projects info.
  #
  def list_projects
    handle_action_exceptions(__method__) do
      cmd_line = ['listprojects']
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Creates a project.
  #
  # == Params:
  #
  # +project+::      The name of the project
  def create_project(project)
    handle_action_exceptions(__method__) do
      cmd_line = ["createproject '#{project}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Deletes a project.
  #
  # == Params:
  #
  # +project+::      The name of the project
  def delete_project(project)
    handle_action_exceptions(__method__) do
      cmd_line = ["deleteproject '#{project}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Creates a project's target.
  #
  # == Params:
  #
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  def create_project_target(target, project, machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "createprojecttarget '#{target}' '#{project}' "\
        "'#{machine}' '#{pool}'"
      ]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Deletes a project's target.
  #
  # == Params:
  #
  # +target+::        The key of the target, use list_machine_targets to get it
  # +project+::       The name of the project
  # +machine+::       The name of the machine as registered with the HCK\HLK
  #                   controller
  # +pool+::          The name of the pool
  def delete_project_target(target, project, machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "deleteprojecttarget '#{target}' "\
        "'#{project}' '#{machine}' '#{pool}'"
      ]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  private

  def do_upload_playlist_file(l_playlist)
    r_path = "#{@winrm_fs.temp_dir}/#{SecureRandom.uuid}.xml"
    @winrm_fs.upload(l_playlist, r_path) do |cb, tb, lp, rp|
      # TODO: Check transfer
    end
    r_path
  end

  def do_list_tests(cmd_line, l_playlist)
    unless l_playlist.nil?
      unless File.exist?(l_playlist)
        raise RToolsHCKError.new('action/list_tests'),
              'Playlist file is not valid.'
      end
      r_playlist = do_upload_playlist_file(l_playlist)
      cmd_line << "-playlist #{r_playlist}"
    end

    handle_return(toolshckcmd(cmd_line.join(' ')))
  end

  public

  # == Description
  #
  # Lists a project target's tests.
  #
  # == Params:
  #
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  # +test_type+::    Assign to manual or auto, (can be nil)
  # +test_status+::  Assign to failed, inqueue, notrun, passed or running,
  #                  (can be nil)
  # +playlist+::     Provide a playlist file path to apply, (can be nil)
  def list_tests(target,
                 project,
                 machine,
                 pool,
                 test_type = nil,
                 test_status = nil,
                 playlist = nil)
    handle_action_exceptions(__method__) do
      cmd_line = ["listtests '#{target}' '#{project}' '#{machine}' '#{pool}'"]
      cmd_line << 'json' if @json
      cmd_line << "-#{test_type}" unless test_type.nil?
      cmd_line << "-#{test_status}" unless test_status.nil?

      do_list_tests(cmd_line, playlist)
    end
  end

  private

  def file_to_outp_dir(r_file_path)
    l_file_path = "#{@outp_dir}/#{guest_basename(r_file_path)}"
    @winrm_fs.download(r_file_path, l_file_path) do |cb, tb, lp, rp|
      # TODO: Check transfer
    end
    l_file_path
  end

  def handle_test_results_json(test_results)
    logs_zip_guest_path = test_results['content']['logszippath']
    test_results['content'].delete('logszippath')
    test_results['content']['guestlogszippath'] = logs_zip_guest_path
    unless @outp_dir.nil?
      logs_zip_host_path = file_to_outp_dir(logs_zip_guest_path)
      test_results['content']['hostlogszippath'] = logs_zip_host_path
    end
    test_results
  end

  def handle_test_results_normal(test_results, stream)
    return false unless test_results

    unless @outp_dir.nil?
      logs_zip_guest_path = stream.split("\n")
                                  .grep(/^Logs zipped to .*/)
                                  .last.split('Logs zipped to ')
                                  .last
                                  .strip
      puts "HOST: Logs zip fetched to #{file_to_outp_dir(logs_zip_guest_path)}"
    end
    test_results
  end

  def handle_test_results(test_results, stream)
    if @json
      return test_results if test_results['result'].eql?('Failure')

      handle_test_results_json(test_results)
    else
      handle_test_results_normal(test_results, stream)
    end
  end

  public

  # == Description
  #
  # Gets a project target's test info.
  #
  # == Params:
  #
  # +test+::         The id of the test, use list_tests action to get it
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  def get_test_info(test, target, project, machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "gettestinfo '#{test}' '#{target}' '#{project}' '#{machine}' "\
        "'#{pool}'"
      ]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Queues a test, use get_test_results action to get the results.
  # (if the test needs two machines to run use -sup flag)
  # (if the test needs the IPv6 address of the support machine use -IPv6 flag)
  #
  # == Params:
  #
  # +test+::         The id of the test, use list_tests action to get it
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  # +sup+::          The name of the support machine as registered with the
  #                  HCK\HLK controller, (can be nil)
  # +ipv6+::         The IPv6 address of the support machine, (can be nil)
  def queue_test(test,
                 target,
                 project,
                 machine,
                 pool,
                 sup = nil,
                 ipv6 = nil)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "queuetest '#{test}' '#{target}' '#{project}' '#{machine}' '#{pool}'"
      ]
      cmd_line << 'json' if @json
      cmd_line << "-sup '#{sup}'" unless sup.nil?
      cmd_line << "-IPv6 '#{ipv6}'" unless ipv6.nil?

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  private

  def do_upload_and_update_filter(l_filter)
    r_filter = run('$env:DTMBIN').strip + SecureRandom.uuid
    @winrm_fs.upload(l_filter, r_filter) do |cb, tb, lp, rp|
      # TODO: Check transfer
    end
    run('pushd $env:DTMBIN')
    run("updatefilters.exe /S #{guest_basename(r_filter)}")
    run('popd')
    @winrm_fs.delete(r_filter)
  end

  public

  # == Description
  #
  # Updates the HCK\HLK controller's filters by giving a local .sql filter file.
  #
  # == Params:
  #
  # +l_filters+::    The local filter .sql file path
  def update_filters(l_filter)
    handle_action_exceptions(__method__) do
      raise 'Filters file not valid.' unless File.exist?(l_filter)

      do_upload_and_update_filter(l_filter)
      @json ? { 'result' => 'Success' } : true
    end
  end

  # == Description
  #
  # Applies the filters on a project's test results.
  #
  # == Params:
  #
  # +project+::      The name of the project
  def apply_project_filters(project)
    handle_action_exceptions(__method__) do
      cmd_line = ["applyprojectfilters '#{project}'"]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Applies the filters on a test result.
  #
  # == Params:
  #
  # +result+::       The index of the test result, use list_test_results action
  #                  to get it
  # +test+::         The id of the test, use list_tests action to get it
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  def apply_test_result_filters(result,
                                test,
                                target,
                                project,
                                machine,
                                pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "applytestresultfilters '#{result}' '#{test}' '#{target}' "\
        "'#{project}' '#{machine}' '#{pool}'"
      ]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Lists a test's results info.
  #
  # == Params:
  #
  # +test+::         The id of the test, use list_tests action to get it
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  def list_test_results(test, target, project, machine, pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "listtestresults '#{test}' '#{target}' '#{project}' '#{machine}' "\
        "'#{pool}'"
      ]
      cmd_line << 'json' if @json

      handle_return(toolshckcmd(cmd_line.join(' ')))
    end
  end

  # == Description
  #
  # Zips a test result's logs to a zip file fetches it to the local machine if
  # logs_dir param was used on initialization.
  #
  # == Params:
  #
  # +result+::       The index of the test result, use list_test_results action
  #                  to get it
  # +test+::         The id of the test, use list_tests action to get it
  # +target+::       The key of the target, use list_machine_targets to get it
  # +project+::      The name of the project
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +pool+::         The name of the pool
  def zip_test_result_logs(result,
                           test,
                           target,
                           project,
                           machine,
                           pool)
    handle_action_exceptions(__method__) do
      cmd_line = [
        "ziptestresultlogs '#{result}' '#{test}' '#{target}' "\
        "'#{project}' '#{machine}' '#{pool}'"
      ]
      cmd_line << 'json' if @json

      stream = toolshckcmd(cmd_line.join(' '))
      test_results = handle_return(stream)
      handle_test_results(test_results, stream)
    end
  end

  private

  def handle_project_package_json(project_package)
    project_package_guest_path = project_package['content']\
                                   ['projectpackagepath']
    project_package['content'].delete('projectpackagepath')
    project_package['content']['guestprojectpackagepath'] = \
      project_package_guest_path
    unless @outp_dir.nil?
      project_package['content']['hostprojectpackagepath'] = \
        file_to_outp_dir(project_package_guest_path)
    end
    project_package
  end

  def parse_project_package_guest_path(stream)
    stream.split("\n")
          .grep(/^Packaged to .*/)
          .last
          .split('Packaged to ')
          .last
          .split('...')
          .first
  end

  def handle_project_package_normal(project_package, stream)
    return false unless project_package

    unless @outp_dir.nil?
      puts 'HOST: Package fetched to '\
           "#{file_to_outp_dir(parse_project_package_guest_path(stream))}"
    end
    project_package
  end

  def handle_project_package(ret_str)
    print 'GUEST: ' unless @json
    project_package = handle_return(ret_str)

    if @json
      return project_package if project_package['result'].eql?('Failure')

      handle_project_package_json(project_package)
    else
      handle_project_package_normal(project_package, ret_str)
    end
  end

  def package_progression_loop(current, maximum, regex_match, handler)
    current += maximum / PROGRESSION_RATE_DIVIDER
    return current if current >= maximum

    steps = toolshckcmd(current.to_s, regex_match).split("\n")
    handler.call(package_progress_info_factory(steps))

    package_progression_loop(current, maximum, regex_match, handler)
  end

  def package_progress_info_factory(progress_steps)
    json_progress_steps = JSON.parse('[' << progress_steps.join(',') << ']')
    { 'stepscount' => progress_steps.size, 'steps' => json_progress_steps }
  end

  def dummy_package_progress_info_handler
    proc do |_progress_package|
      nil
    end
  end

  def package_progression_first_step(cmd_line, regex_match, handler)
    steps = toolshckcmd(cmd_line, regex_match).split("\n")
    handler.call(package_progress_info_factory(steps))
    [JSON.parse(steps[-1])['current'], JSON.parse(steps[-1])['maximum']]
  end

  def package_progression_last_step(current, handler)
    stream = toolshckcmd(current.to_s).split("\n")
    handler.call(package_progress_info_factory(stream[0..-2]))
    stream[-1]
  end

  def handle_create_project_package(cmd_line, project, handler)
    regex_match = /^toolsHCK@.*:createprojectpackage\(#{project}\)>/

    current, maximum = package_progression_first_step(cmd_line, regex_match,
                                                      handler)
    current = package_progression_loop(current, maximum, regex_match, handler)

    ret_str = package_progression_last_step(current, handler)

    handle_project_package(ret_str)
  rescue Net::ReadTimeout, Errno::ECONNRESET, Errno::EPIPE => e
    raise RToolsHCKConnectionError.new('toolsHCK'),
          "[#{e.class}] #{e.message}", e.backtrace
  end

  # Progression rate divider, used for the synchronization with the controller
  PROGRESSION_RATE_DIVIDER = 30

  public

  # == Description
  #
  # Creates a project's package and saves it to a file at <package> if used,
  # if not to %TEMP%\prometheus_packages\..., also fetches the package file to
  # the local machine if outp_dir param was used on initialization.
  #
  # == Params:
  #
  # +project+::      The name of the project
  # +handler+::      The progress info handler, (can be nil), usage example:
  #                    handler = proc { |progress_package|
  #                      puts progress_package['stepscount']
  #                    }
  #                  progress_package is in JSON format and it has:
  #                  1. 'stepscount': a numeric progression steps count
  #                  1. 'steps': an array of 'stepscount' JSON entries that
  #                     each entry represents a single progression step's
  #                     progress info, each entry's content:
  #                     i. 'current': current progress counter value
  #                     i. 'maximum': maximum progress counter value
  #                     i. 'message': progress info message
  #
  def create_project_package(project, handler = nil)
    handle_action_exceptions(__method__) do
      cmd_line = ["createprojectpackage '#{project}' -rph"]
      cmd_line << 'json' if @json

      handler = dummy_package_progress_info_handler if handler.nil?
      handle_create_project_package(cmd_line.join(' '), project, handler)
    end
  end

  # == Description
  #
  # Gets a machine's ip address.
  #
  # == Params:
  #
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +ipv6+::         Get IPv6 address, :ipv6 to enable, disabled by default
  def get_machine_ip(machine, ipv6 = false)
    handle_action_exceptions(__method__) do
      cmd_line = ['ping -n 1']
      cmd_line << (ipv6 ? '-6' : '-4')
      cmd_line << machine
      ip = run(cmd_line.join(' ')).split("\r\n")[1].split(' ')[2].slice!(1..-2)
      @json ? { 'result' => 'Success', 'content' => ip } : ip
    end
  end

  # == Description
  #
  # Shuts down or restarts the studio, (you will need to reconnect after this).
  #
  # == Params:
  #
  # +restart+::      Restarts the machine, :restart to enable, disabled by
  #                  default
  def shutdown(restart = false)
    handle_action_exceptions(__method__) do
      cmd_line = ['shutdown -f -t 00']
      cmd_line << (restart ? '-r' : '-s')

      run(cmd_line.join(' '))
      @json ? { 'result' => 'Success' } : true
    end
  end

  # == Description
  #
  # Shuts down or restarts a machine.
  #
  # == Params:
  #
  # +machine+::      The name of the machine as registered with the HCK\HLK
  #                  controller
  # +restart+::      Restarts the machine, :restart to enable, disabled by
  #                  default
  def machine_shutdown(machine, restart = false)
    handle_action_exceptions(__method__) do
      cmd_line = ['shutdown -f -t 00']
      cmd_line << (restart ? '-r' : '-s')

      machine_run(machine, cmd_line.join(' '))
      @json ? { 'result' => 'Success' } : true
    end
  end

  private

  def do_upload_driver_package_files(machine, l_directory)
    fm = WinRM::FS::FileManager.new(machine_connection(machine))
    r_directory = "#{fm.temp_dir}/#{SecureRandom.uuid}"
    fm.upload(l_directory, r_directory) do |cb, tb, lp, rp|
      # TODO: Check transfer
    end
    r_directory
  end

  def do_install_machine_driver_package(machine,
                                        install_method,
                                        l_directory,
                                        inf_file)
    r_directory = do_upload_driver_package_files(machine, l_directory)
    windows_path = "#{r_directory}/#{inf_file}".tr('/', '\\')
    command = case install_method
              when 'PNP'
                "pnputil -i -a #{windows_path}"
              when 'NON-PNP'
                'RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection ' \
                "DefaultInstall 128 #{windows_path}"
              end
    machine_run(machine, command)
  end

  public

  # == Description
  #
  # Installs a driver package, (.inf file), on a machine.
  #
  # == Params:
  #
  # +machine+::      The name of the machine
  # +l_directory+::  The local directory which has the driver package,
  #                  (.inf file)
  # +inf_file+::     The .inf file name
  def install_machine_driver_package(machine,
                                     install_method,
                                     l_directory,
                                     inf_file)
    handle_action_exceptions(__method__) do
      unless File.exist?(File.join(l_directory, inf_file))
        raise 'Inf file not valid.'
      end

      do_install_machine_driver_package(machine,
                                        install_method,
                                        l_directory,
                                        inf_file)
      @json ? { 'result' => 'Success' } : true
    end
  end

  # == Description
  #
  # Tries to regain the connection to the guest machine using the given
  # credentials and addresses on initialization.
  #
  def reconnect
    handle_action_exceptions(__method__) do
      close_for_reconnect
      load_winrm_ps
      load_toolshck
      @json ? { 'result' => 'Success' } : true
    end
  end

  private

  def close_for_reconnect
    unload_toolshck
    unload_winrm_ps
  rescue StandardError => e
    log_exception(e)
  end

  def unload_winrm_ps
    logger('debug', 'close/winrm') { 'unloading winrm shell...' }
    @winrm_ps.close
    logger('debug', 'close/winrm') { 'winrm shell unloaded!' }
  rescue StandardError => e
    log_exception(e)
  end

  def unload_toolshck_telnet
    logger('debug', 'close/toolsHCK') { 'unloading toolsHCK telnet...' }
    @toolshck_telnet.close
    logger('debug', 'close/toolsHCK') { 'toolsHCK telnet unloaded!' }
  end

  def unload_toolshck_shell
    logger('debug', 'close/toolsHCK') { 'unloading toolsHCK shell...' }
    @toolshck_telnet.cmd('exit')
    logger('debug', 'close/toolsHCK') { 'toolsHCK shell unloaded!' }
  end

  def unload_toolshck
    unload_toolshck_shell
    unload_toolshck_telnet
  rescue StandardError => e
    log_exception(e)
  end

  def check_connection
    cmd_line = ['ping']

    if toolshckcmd(cmd_line.join(' ')).include?('pong')
      @json ? { 'result' => 'Success' } : true
    else
      raise RToolsHCKActionError.new('action/connection_check'),
            "something went wrong, 'pong' was not received."
    end
  end

  public

  # == Description
  #
  # Checks if connection is still alive.
  #
  def connection_check
    handle_action_exceptions(__method__) do
      check_connection(json)
    end
  rescue RToolsHCKConnectionError => e
    if @json
      { 'result' => 'Failure', 'message' => e.message }
    else
      puts "WARNING: #{e.message}"
      false
    end
  end

  # == Description
  #
  # Closes the instance and shuts down the studio.
  #
  def close_and_shutdown
    handle_action_exceptions(__method__) do
      unload_toolshck
      shutdown
      unload_winrm_ps
      logger('debug', 'close') { 'done!' }
      @closed = true
      @json ? { 'result' => 'Success' } : true
    end
  end

  # == Description
  #
  # Closes the instance.
  #
  def close
    handle_action_exceptions(__method__) do
      unload_toolshck
      unload_winrm_ps
      logger('debug', 'close') { 'done!' }
      @closed = true
      @json ? { 'result' => 'Success' } : true
    end
  end

  # == Description
  #
  # Boolean method to the instance being closed.
  #
  def closed?
    @closed
  end
end
# rubocop:enable Metrics/ClassLength, Metrics/ParameterLists
