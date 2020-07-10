# NetworkDatasetTbx

## ports_info2dict.jl
Example of use ports_info2dict.jl. Domain name might be replaced by IP address. \
e. g. nmap("cvut.cz")  ≡ nmap("147.32.3.202")  
```julia
julia> include("ports_info2dict.jl")
julia> dict = nmap("cvut.cz")
Dict{Any,Any} with 7 entries:
  25  => node(25, "tcp", "closed", "smtp")
  80  => node(80, "tcp", "open", "http")
  443 => node(443, "tcp", "open", "https")
  143 => node(143, "tcp", "open", "imap")
  993 => node(993, "tcp", "open", "imaps")
  995 => node(995, "tcp", "open", "pop3s")
  110 => node(110, "tcp", "open", "pop3")
julia> dict[25].port_id
25
julia> dict[25].protocol
"tcp"
julia> dict[25].state
"closed"
julia> dict[25].service
"smtp"
```

## dns2ip.jl
By DNS returns IP address.
Example:
convert_dns2ip("fel.cvut.cz")

Tested with:
macOS Catalina v10.15.5.

```julia
julia> include("dns2ip.jl")
julia> convert_dns2ip("cvut.cz")
"147.32.3.202"
```
