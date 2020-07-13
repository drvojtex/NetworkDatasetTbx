# includes:
include("dns2ip.jl")
include("ports_info2dict.jl")
include("threatcrowd2dict.jl")

##############################################################

# Node of information about each domain.
struct thread_node
	ip::String
	dns::String
	ports::Dict
	neighbours::Dict
end

# Dictionary of neighbours of root server.
main_dict = Dict()

##############################################################

# Main function to start probe and create json file.
function probe_server(root_server::Domain)
	root_dict = threatcrowd_dict(root_server)
	probe_root(root_dict)
	out = thread_node(convert_dns2ip(root_server.s), root_server.s, nmap(convert_dns2ip(root_server.s)), main_dict)
	open("$(root_server.s).json", "w") do f
		JSON.print(f, out, 4)
	end
end

function probe_server(root_server::Ip)
	root_dict = threatcrowd_dict(root_server)
	probe_root(root_dict)
	out = thread_node("", root_server.s, nmap(root_server.s), main_dict)
	open("$(root_server.s).json", "w") do f
		JSON.print(f, out, 4)
	end
end

##############################################################

# Probe neigbours of root.

function probe_root(root_dict::Dict)
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
