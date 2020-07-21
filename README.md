# NetworkDatasetTbx

Example of use:
```julia
julia> include("main.jl")  # Load toolbox.
julia> database(Domain("elmag.fel.cvut.cz"))  # Create database.
julia> load_arrange_JSON("elmag.fel.cvut.cz.json")
julia> create_graph("graph")
Process(`open graph.pdf`, ProcessExited(0))
```
Output as JSON (database) and PDF (graph) files.


<img
src=“kozvojtex/NetworkDatasetTbx/blob/master/graph.pdf”
raw=true
alt=“Subject Pronouns”
style=“margin-right: 10px;”
/>


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

## location2dict.jl
Returns dictionary with information about IP (city, hostname, location - coordinates, rigion (parent city), provider organization, timezone, country). 
Example:
location(Ip("147.32.3.202"))

```julia
julia> include("location2dict.jl")
julia> location(Ip("147.32.3.202"))
Dict{String,Any} with 7 entries:
  "city"     => "Prague"
  "hostname" => "webmm-pub.is.cvut.cz"
  "loc"      => "50.0880,14.4208"
  "region"   => "Hlavní město Praha"
  "org"      => "AS2852 CESNET z.s.p.o."
  "timezone" => "Europe/Prague"
  "country"  => "CZ"
```

## threatcrowd2dict.jl
Probe given server.
threatcrowd_dict(hash::Hash)
threatcrowd_dict(email::Mail)
threatcrowd_dict(ip_address::Ip)
threatcrowd_dict(domain_name::Domain)

Example:
threatcrowd_dict(Domain("fel.cvut.cz"))

```julia
julia> include("threatcrowd2dict.jl")
julia> threatcrowd_dict(Domain("fel.cvut.cz"))
Dict{String,Any} with 8 entries:
  "resolutions"   => Any[Dict{String,Any}("ip_address"=>"-","last_resolved"=>"0000-00-00"), Dict{String,Any}("ip_address"=>"147.32.192.12","last_resolved"=…
  "emails"        => Any[""]
  "subdomains"    => Any["informatika.fel.cvut.cz", "fyzika.fel.cvut.cz", "gitlab.fel.cvut.cz", "aic.fel.cvut.cz", "dce.fel.cvut.cz", "aa4cc.dce.fel.cvut.c…
  "references"    => Any[]
  "hashes"        => Any[]
  "votes"         => 0
  "response_code" => "1"
  "permalink"     => "https://www.threatcrowd.org/domain.php?domain=fel.cvut.cz"
```
