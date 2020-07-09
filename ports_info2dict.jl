
"""
With 'nmap tool' finds information about server ports.
Data in dictionary (key: port_id; value: node).
Example:
nmap("fel.cvut.cz")
nmap("147.32.3.202")

Nmap tool:
Nmap 7.80 ( https://nmap.org ) GNU GPL License.
"""

using EzXML

# Data node struct.
mutable struct node
    port_id::Int
    protocol::String
    state::String
    service::String
end

function nmapXML_2_dict(filename::String)
    """
    Converts info about ports from XML file to dictionary.
    :param filename: XML filename (String).
    :return: dictionary (key: port_id; value: node).
    """

    dict = Dict()

    # Read a document from a file and set a root.
    file = joinpath(dirname(@__FILE__), filename)
    doc = root(readxml(file))

    # Extract data from xml file.
    for tag in eachelement(doc)
        if tag.name == "host"
            for sub_tag in eachelement(tag)
                if sub_tag.name == "ports"
                    for minor_tag in eachelement(sub_tag)
                        if minor_tag.name == "port"
                            data = node(0, "", "", "")
                            data.port_id = parse(Int, minor_tag["portid"])
                            data.protocol = minor_tag["protocol"]
                            for element in eachelement(minor_tag)
                                if element.name == "state"
                                    data.state = element["state"]
                                end
                                if element.name == "service"
                                    data.service = element["name"]
                                end
                            end
                            dict[data.port_id] = data
                        end   
                    end
                    break
                end
            end
            break
        end
    end
    return dict
end

function nmap(server::String)
    (outread, outwrite) = redirect_stdout()
    run(`nmap $(server) -oX tmp_$(server).xml`)
    output = nmapXML_2_dict("tmp_$(server).xml")
    rm("tmp_$(server).xml")    
    return output
end
