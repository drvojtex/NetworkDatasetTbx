
using JSON

info_dict = Dict()

function ipinfo2dict(server::String)
    open("tmp_$(server).json", "r") do f
        global info_dict
        dicttxt = read(f, String)
        info_dict = JSON.parse(dicttxt)
    end
    delete!(info_dict, "postal")
    delete!(info_dict, "ip")
    delete!(info_dict, "readme")
end

function location(server::Ip)
    server = server.s
    run(`curl https://ipinfo.io/$(server) -o tmp_$(server).json -s`)
    ipinfo2dict(server)
    rm("tmp_$(server).json")
    return info_dict
end
