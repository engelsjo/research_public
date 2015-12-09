require 'whois'

zone_file_path = '/Users/joshuaengelsma/git/tld_file_parser/data/zonefiles/'

c = Whois::Client.new(timeout: 10)

#loop through every zone file
Dir.foreach(zone_file_path) do |item|
	next if item == '.' or item == '..'
	File.open(zone_file_path+item, "r") do |file_handle|
  		#loop through every line in file
  		file_handle.each_line do |line|
  			begin
  				domain_name = line.split()[0]
  				whois_rec = c.lookup(domain_name)
  				puts "Domain: " + domain_name
    			puts "Registrar: " + whois_rec.registrar.name
    			puts "Created: " + whois_rec.created_on.to_s
    		rescue
    			print "."
    		end
  		end
	end
end
