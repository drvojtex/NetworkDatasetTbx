
using HTTP, JSON


# Create data types.

abstract type threatcrowdType end;
struct Domain <: threatcrowdType
	s::String
end
struct Ip <:threatcrowdType
	s::String
end


# Request functions:

function threatcrowd_dict(domain_name::Domain)
    request = HTTP.request("GET", "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="*domain_name.s)
    return JSON.parse(String(request.body))
end

function threatcrowd_dict(ip_address::Ip)
    request = HTTP.request("GET", "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip="*ip_address.s)
    return JSON.parse(String(request.body))
end
