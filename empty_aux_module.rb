##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Name of module',
      'Description'    => %q{
      This is the description of the module
      },
      'References'     =>
        [
          ['URL', 'http://site.of/the/disclosure']
        ],
      'Author'         =>
        [
          'who discovered it', #discovery
          'mtibbett', #module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'DD MMM YYYY'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The relative URI', '/']),
      ], self.class)
  end

  def check
    Msf::Exploit::CheckCode::Safe
  end

  def run
  end
end
