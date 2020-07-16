
using DataStructures

# includes:
include("dns2ip.jl")
include("ports_info2dict.jl")
include("threatcrowd2dict.jl")
include("location2dict.jl")

##############################################################

# Node of information about each domain.
mutable struct thread_node
	ip::String
	dns::String
	ports::Dict
    neighbours::Array
    location::Dict
end

# Dictionary of neighbours of root server.
main_dict = Dict()
# Stack of unexplored servers.
main_stack = Stack{Array}()
# Array of visited vertexes.
main_visited_vertexes = []

##############################################################

function database(root_server::Domain)
    global main_dict

    # probe root
    root_dict = threatcrowd_dict(root_server)
    tmp_neighbours = extract_neighbours(root_dict)
    root_ip = convert_dns2ip(root_server.s)
    tmp_node = thread_node(root_ip, root_server.s, nmap(root_server.s), tmp_neighbours, location(Ip(root_ip)))
    main_dict[root_server.s] = tmp_node
    append!(main_visited_vertexes, [root_server])
    # probe neighbours of root server
    while !isempty(main_stack)
        @show main_stack
        vertex = pop!(main_stack)[1]
        vertex_dict = threatcrowd_dict(vertex)
        tmp_neighbours = extract_neighbours(vertex_dict)
        if typeof(vertex) == Domain
            vertex_ip = convert_dns2ip(vertex.s)
            tmp_node = thread_node(vertex_ip, vertex.s, nmap(vertex.s), tmp_neighbours, location(Ip(vertex_ip)))
        elseif typeof(vertex) == Ip
            tmp_node = thread_node(vertex.s, "", nmap(vertex.s), tmp_neighbours, location(Ip(vertex.s)))
        elseif typeof(vertex) == Mail
            tmp_node = thread_node("", vertex.s, Dict(), tmp_neighbours, Dict())
        end
        main_dict[vertex.s] = tmp_node
    end

    # store to json file
    open("$(root_server.s).json", "w") do f
		JSON.print(f, main_dict, 4)
	end
end

function extract_neighbours(tcMessage::Dict)
    global main_stack
    global main_visited_vertexes
    neighbours_arr = []
    if haskey(tcMessage, "resolutions")
        res_dict = tcMessage["resolutions"]
        for neighbour in res_dict
            if haskey(neighbour, "ip_address")
                ip_address = Ip(neighbour["ip_address"])
                if ip_address.s != "-"
                    append!(neighbours_arr, [ip_address])
                    if !(ip_address in main_visited_vertexes)
                        push!(main_stack, [ip_address])
                        append!(main_visited_vertexes, [ip_address])
                    end
                end
            end
            if haskey(neighbour, "domain")
                domain = Domain(neighbour["domain"])
                append!(neighbours_arr, [domain])
                if !(domain in main_visited_vertexes)
                    push!(main_stack, [domain])
                    append!(main_visited_vertexes, [domain])
                end
            end
        end
    end
    if haskey(tcMessage, "emails")
        emails = tcMessage["emails"]
        for email in emails
            email = Mail(email)
            if length(email.s) > 0
                append!(neighbours_arr, [email])
                if !(email in main_visited_vertexes)
                    push!(main_stack, [email])
                    append!(main_visited_vertexes, [email])
                end
            end
        end
    end
    if haskey(tcMessage, "subdomains")
        subdomains = tcMessage["subdomains"]
        for subdomain in subdomains
            if length(subdomain) > 0
                subdomain = Domain(subdomain)
                append!(neighbours_arr, [subdomain])
                if !(subdomain in main_visited_vertexes)
                    push!(main_stack, [subdomain])
                    append!(main_visited_vertexes, [subdomain])
                end
            end
        end
    end
    if haskey(tcMessage, "domains")
        domains = tcMessage["domains"]
        for domain in domains
            domain = Domain(domain)
            append!(neighbours_arr, [domain])
            if !(domain in main_visited_vertexes)
                push!(main_stack, [domain])
                append!(main_visited_vertexes, [domain])
            end
        end
    end
    return neighbours_arr
end
