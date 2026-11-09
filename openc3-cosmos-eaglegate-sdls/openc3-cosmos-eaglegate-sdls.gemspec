# encoding: ascii-8bit

# Create the overall gemspec
Gem::Specification.new do |s|
  s.name = 'openc3-cosmos-eaglegate-sdls'
  s.summary = 'OpenC3 openc3-cosmos-eaglegate-sdls plugin: SDLS transfer frame checks in front of the EagleGate firewall'
  s.description = <<-EOF
    Extension of the openc3-cosmos-eaglegate plugin. Receives CCSDS TM transfer
    frames protected with SDLS (CCSDS 355.0-B-2), checks them (spacecraft and
    virtual channel, SPI binding, anti-replay, frame counters) and hands the
    packets inside to the EagleGate firewall. Requires openc3-cosmos-eaglegate.
  EOF
  s.licenses = 'MIT'
  s.authors = ['Cobhan Kale','Emmanuel Romero Gonzalez']
  s.email = ['cobhank@berkeley.edu','emmanuel_romero@berkeley.edu']
  s.homepage = 'https://github.com/CobhanK/EagleGate/'
  s.platform = Gem::Platform::RUBY
  s.required_ruby_version = '>= 3.0'

  if ENV['VERSION']
    s.version = ENV['VERSION'].dup
  else
    time = Time.now.strftime("%Y%m%d%H%M%S")
    s.version = '0.0.0' + ".#{time}"
  end
  # Prefer pyproject.toml over requirements.txt
  python_dep_file = if File.exist?('pyproject.toml')
    'pyproject.toml'
  else
    'requirements.txt'
  end
  # Python caches from running the tests are not part of the plugin
  s.files = Dir.glob("{targets,lib,public,tools,microservices}/**/*").reject { |f| f.include?('__pycache__') } +
    %w(Rakefile README.md LICENSE.md plugin.txt) + [python_dep_file]

  s.metadata = {
    # These fields are used when you submit your plugin to the OpenC3 Store at store.openc3.com
    # See this help page for more detail: https://store.openc3.com/help/guidelines
    "source_code_uri" => "https://github.com/CobhanK/EagleGate",
    "openc3_store_title" => "eaglegate-sdls",
    "openc3_store_description" => "SDLS transfer frame checks for the EagleGate telemetry firewall (requires openc3-cosmos-eaglegate)",
    "openc3_store_keywords" => "firewall, sdls, ccsds, transfer frame, eaglegate",
    "openc3_cosmos_minimum_version" => "6.0.0", # OPTIONAL
    "openc3_store_access_type" => "public" # OPTIONAL
  }
end
