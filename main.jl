
include("dns2ip.jl")
include("ports_info2dict.jl")
include("threatcrowd2dict.jl")

struct thread_node
	ip::String
	dns::String
	ports::Dict
	neighbours::Dict
end


main_dict=Dict()


function probe_server(root_server::Domain)
	root_dict = threatcrowd_dict(root_server)
	for ip_address in root_dict["resolutions"]
		ip_address = ip_address["ip_address"]
		@show ip_address
		if ip_address != "-"
			main_dict[ip_address] = thread_node(ip_address, "", nmap(ip_address), Dict())
		end
	end
	for email in root_dict["emails"]
		if length(email) > 0
			main_dict[email] = threatcrowd_dict(Mail(email))["domains"]
		end
	end
	for subdomain in root_dict["subdomains"]
		tmp = convert_dns2ip(subdomain)
		key = subdomain
		if tmp != ""
			key = tmp
		end
		@show subdomain
		main_dict[key] = thread_node(key, subdomain, nmap(key), Dict())
	end
end


#network = Dict("123.2"=> thread_node("123.2", "asd.com", Dict(12=>"open", 24=>"closed"), Dict("343.2"=> thread_node("343.2", "qwe.com", Dict(24=>"open"), Dict()), "311.2" => thread_node("311.2", "tze.com", Dict(14=>"open", 98=>"closed"), Dict()) )))
#JSON.print(stdout, network, 4)
