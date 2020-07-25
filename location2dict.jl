
using JSON

function location(server::Ip)
    server = server.s
    r = nothing
    try
        p=pipeline(`whois $(server) > $(server).txt`, `grep 'netname\|descr\|country'`)
        r=split(replace(read(p, String), " "=>""), "\n")
    catch ex
        return Dict()
    end
    info_dict = Dict("netname"=>[], "descr"=>[], "country"=>[])
    for a in r
        if a != ""
            key = split(a, ":")[1]
            val = split(a, ":")[2]
            append!(info_dict[key], [val])
        end
    end
    return info_dict
end
