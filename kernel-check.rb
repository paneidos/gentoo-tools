#!/usr/bin/env ruby
# Copyright 2015 Sernin van de Krol

require 'zlib'
require 'optparse'
require 'ostruct'
require 'pp'

class OptParser
  def self.parse(args)
    options = OpenStruct.new
    options.emerge_opts = []
    options.kernel_config = nil
    options.kernel_version = nil

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options] [--] [emerge arguments]"

      opts.separator ""
      opts.separator "Used to check your kernel configuration for wrong settings."
      opts.separator "Several options you can pass to emerge can also be passed to this program."

      opts.separator ""
      opts.separator "Operation:"
      opts.separator "  If no emerge arguments are given, the existing package database"
      opts.separator "  will be checked."
      opts.separator "  If there are arguments, emerge will be run with --pretend --verbose and"
      opts.separator "  the output will be parsed and the ebuilds scanned for kernel config options."

      opts.separator ""
      opts.separator "Specific options:"

      opts.on("-c", "--config CONFIG", "Specify kernel config file to check", "(default: /usr/src/linux/.config", " or /proc/config.gz)") do |config_file|
        options.kernel_config = config_file
      end

      opts.on("-k", "--kernel VERSION", "Specify kernel version to assume", "(default: autodetect, based on config path)") do |version|
        options.kernel_version = version
      end

      opts.on("-u", "--update", "Run emerge with --update (-u)") do
        options.emerge_opts << "--update"
      end

      opts.on("-D", "--deep [DEPTH]", "Run emerge with --deep (-D)") do |depth|
        options.emerge_opts << "--deep"
        options.emerge_opts << depth unless depth.nil?
      end

      opts.on("-N", "--newuse", "Run emerge with --newuse (-N)") do
        options.emerge_opts << "--newuse"
      end

      opts.on("--nodeps", "Run emerge with --nodeps") do
        options.emerge_opts << "--nodeps"
      end

      opts.on("-v", "--verbose", "Ignored") do
        #
      end

      opts.on("-a", "--ask", "Ignored") do
        #
      end

      opts.on("-p", "--pretend", "Ignored") do
        #
      end

      opts.separator ""
      opts.separator "Common options:"
      opts.on("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      opts.separator ""
      opts.separator "Examples:"
      opts.separator "  #{$0} -vuaDN @world"
      opts.separator "  #{$0} --nodeps nvidia-drivers"

      opts.separator ""
      opts.separator "To stop parsing options after the first non-option argument,"
      opts.separator "set POSIXLY_CORRECT to 1."
    end

    opts.parse!(args)
    options
  end
end

class KernelConfigChecker
  def initialize
    @options = {}
  end

  def add_package_options(package, options)
    options.each do |option|
      fatal = true
      state = :enabled
      if option[0] == "~"
        fatal = false
        option = option[1..-1]
      end
      if option[0] == "!"
        state = :disabled
        option = option[1..-1]
      end
      @options[option] ||= { enabled: [], disabled: [] }
      @options[option][state] << [fatal, package]
    end
  end

  def print_conflicts
    has_conflicts = false
    @options.each do |name, option|
      if option[:enabled].size > 0 && option[:disabled].size > 0
        has_conflicts = true
        puts "Conflict for CONFIG_#{name} found:"
        puts "These packages want CONFIG_#{name} enabled: #{option[:enabled].map(&:last).map(&:to_s).join(", ")}"
        puts "These packages want CONFIG_#{name} disabled: #{option[:disabled].map(&:last).map(&:to_s).join(", ")}"
      end
    end
    # puts "No conflicts" unless has_conflicts
  end

  def check_config_file(path)
    enabled_options = {}
    option_names = @options.keys
    check_line = ->(line) {
      line = line.chop
      if match = line.match(/\ACONFIG_([^=]+)=(.*)\z/)
        if option_names.include?(match[1]) && match[2] != '""' && match[2] != "n"
          enabled_options[match[1]] = match[2]
        end
      end
    }
    contents = if path =~ /\.gz\z/
      Zlib::GzipReader.open(path) { |gz| gz.each_line(&check_line) }
    else
      File.open(path) { |f| f.each_line(&check_line) }
    end
    @options.each do |name, option|
      if option[:enabled].size > 0 && !enabled_options[name]
        puts "CONFIG_#{name} is not enabled when it should be. (#{option[:enabled].map(&:last).map(&:to_s).join(", ")})"
      end
      if option[:disabled].size > 0 && enabled_options[name]
        puts "CONFIG_#{name} is enabled when it should not be. (#{option[:disabled].map(&:last).map(&:to_s).join(", ")})"
      end
    end
  end
end

class Package
  attr_accessor :use_flags
  attr_reader :category, :name, :version

  def initialize(category, name, version, use_flags = [])
    @category = category
    @name = name
    @version = version
    @use_flags = use_flags
  end

  def ebuild_exists?
    File.exist?(ebuild_path)
  end

  def ebuild_path
    "/usr/portage/#{@category}/#{@name}/#{@name}-#{@version}.ebuild"
  end

  def config_options_from_ebuild(kernel_version = nil)
    config_options = []
    all_options = {
      package_without_flags => []
    }
    contents = File.read(ebuild_path)
    if contents.index("CONFIG_CHECK")
      results = contents.scan(/^\s+(local\s+)?CONFIG_CHECK\+?="(?<config>[^"]+)"/)
      config_options = results.flatten.map{|s| s.split(/\s+/)}.flatten.reject{|s| s == "" || s == "${CONFIG_CHECK}" || s == "$CONFIG_CHECK" }.compact
      all_options[package_without_flags] = config_options.dup

      # Find conditional flags based on USE flags
      contents.scan(/^\s+use\s+(?<flag>\S+)\s+(?<type>\|\||&&)\s+CONFIG_CHECK\+?="(?<config>[^"]+)"/).each do |match|
        flag = match[0]
        type = match[1]
        options = match[2].split(/\s+/).reject{|s| s == "" || s == "${CONFIG_CHECK}" || s == "$CONFIG_CHECK" }.compact
        if type == "||" && use_flags.include?("-" + flag)
          all_options[package_with_flag("-" + flag)] = options
          config_options.concat(options)
        elsif type == "&&" && use_flags.include?(flag)
          all_options[package_with_flag(flag)] = options
          config_options.concat(options)
        end
      end

      # Find conditional flags based on kernel version
      contents.scan(/^\s+kernel_is\s+-(?<compare>lt)\s+(?<version>\d+(\s+\d+)*)\s+(?<type>\|\||&&)\s+CONFIG_CHECK\+?="(?<config>[^"]+)"/).each do |match|
        compare = match[0]
        version = match[1].split(/\s+/)
        kversion = Gem::Version.new(version.join("."))
        type = match[2]
        options = match[3].split(/\s+/).reject{|s| s == "" || s == "${CONFIG_CHECK}" || s == "$CONFIG_CHECK" }.compact
        positive = if kernel_version.nil?
          type == "&&"
        else
          case compare
          when "lt"
            kernel_version < kversion
          when "gt"
            kernel_version > kversion
          when "lte"
            kernel_version <= kversion
          when "gte"
            kernel_version >= kversion
          when "eq"
            kernel_version == kversion
          else
            type == "&&"
          end
        end
        if (positive && type == "&&") || (!positive && type == "||")
          all_options[package_with_flag("linux_kernel_#{compare}_#{version.join('_')}")] = options
        end
      end

      if config_options.size == 0
        puts "Found CONFIG_CHECK, but could not parse ebuild for #{self.to_s}"
      end
    end
    all_options
  end

  def eql?(other)
    category == other.category && name == other.name && version == other.version && use_flags.sort == other.use_flags.sort
  end

  def hash
    category.hash ^ name.hash ^ version.hash ^ use_flags.sort.join(",").hash
  end

  def package_with_flag(flag)
    self.class.new(@category, @name, @version, [flag])
  end

  def package_without_flags
    self.class.new(@category, @name, @version)
  end

  def self.parse_emerge_line(emerge_line)
    match = emerge_line.match(/\A\[ebuild .......\] ([^ ]+) /)
    return nil unless match
    package = self.parse_atom(match[1])
    flags = emerge_line.scan(/([0-9A-Z_]+)="([^"]+)"/)
    use_flags = []
    flags.each do |flag|
      prefix = ""
      prefix = flag[0].downcase + "_" if flag[0] != "USE"
      flag[1].split(" ").each do |flag_atom|
        flag_atom = flag_atom[1..-2] if flag_atom[0] == "(" && flag_atom[-1] == ")"
        flag_atom = flag_atom[1..-2] if flag_atom[0] == "{" && flag_atom[-1] == "}"
        flag_atom = flag_atom[0..-2] if flag_atom[-1] == "*"
        flag_atom = flag_atom[0..-2] if flag_atom[-1] == "%"
        negate = ""
        if flag_atom[0] == "-"
          negate = "-"
          flag_atom = flag_atom[1..-1]
        end
        use_flags << "#{negate}#{prefix}#{flag_atom}"
      end
    end
    package.use_flags = use_flags
    package
  end

  def self.parse_atom(atom)
    atom = atom.split(":").first
    if match = atom.match(/\A(.*)-([^-]+-r\d+)\z/)
      category, name = match[1].split("/")
      version = match[2]
      Package.new(category, name, version)
    elsif match = atom.match(/\A(.*)-([^-]+)\z/)
      category, name = match[1].split("/")
      version = match[2]
      Package.new(category, name, version)
    else
      nil
    end
  end

  def to_s
    atom = "=#{@category}/#{@name}-#{@version}"
    if @use_flags && @use_flags.size > 0
      atom + "[#{@use_flags.sort.join(',')}]"
    else
      atom
    end
  end

  def inspect
    "#<Package: =#{@category}/#{@name}-#{@version}>"
  end
end

options = OptParser.parse(ARGV)

if options.kernel_config.nil?
  if File.exist?("/usr/src/linux/.config")
    options.kernel_config = "/usr/src/linux/.config"
  elsif File.exist?("/proc/config.gz")
    options.kernel_config = "/proc/config.gz"
  else
    puts "No kernel config file found"
    exit 1
  end
end

if options.kernel_version.nil?  
  if options.kernel_config == "/proc/config.gz"
    options.kernel_version = Gem::Version.new(`uname -r`.split("-").first) rescue nil
  elsif options.kernel_config =~ /\/.config\z/
    kernel_dir = File.readlink(File.dirname(options.kernel_config))
    kernel_name = File.basename(kernel_dir)
    if kernel_name =~ /\Alinux-\d/
      options.kernel_version = Gem::Version.new(kernel_name[6..-1].split("-").first) rescue nil
    end
  end
else
  options.kernel_version = Gem::Version.new(options.kernel_version.split("-").first) rescue nil
end

if options.kernel_version.nil?
  puts "WARNING: No kernel version known, ignoring all kernel version checks"
# else
#   puts "Kernel version: #{options.kernel_version}"
end

config_checker = KernelConfigChecker.new

if ARGV.size == 0
  # Collect info from installed packages
  current_dir = Dir.getwd
  Dir.chdir "/var/db/pkg"
  environments = Dir["*/*/environment.bz2"]

  environments.each do |environment|
    result = `bzcat #{environment} | grep "declare -- CONFIG_CHECK"`.chop
    if result.size > 0 && match = result.match(/\Adeclare -- CONFIG_CHECK="([^"]+)"\z/)
      package = Package.parse_atom(File.dirname(environment))
      config_options = match[1].split(/\s+/).reject{ |s| s == "" }
      config_checker.add_package_options(package, config_options)
    end
  end
  Dir.chdir current_dir
else
  # Collect info from emerge output
  emerge_command = ["emerge", "--pretend", "--verbose"] + options.emerge_opts + ARGV
  result = `#{emerge_command.join(" ")}`.split("\n")
  result.each do |line|
    if package = Package.parse_emerge_line(line)
      # puts package
      if package.ebuild_exists?
        config_options = package.config_options_from_ebuild(options.kernel_version)
        config_options.each do |package, config_options|
          config_checker.add_package_options(package, config_options)
        end
      else
        puts "WARNING: NO EBUILD FOR #{package}"
      end
    end
  end
end

config_checker.print_conflicts
config_checker.check_config_file(options.kernel_config)
