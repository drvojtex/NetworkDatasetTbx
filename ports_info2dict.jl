
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
struct node
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

    # Define variables.
    dict = Dict()
    tmp_port_id = 0
    tmp_protocol = ""
    tmp_state = ""
    tmp_service = ""

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
                            tmp_port_id = parse(Int, minor_tag["portid"])
                            tmp_protocol = minor_tag["protocol"]
                            for element in eachelement(minor_tag)
                                if element.name == "state"
                                    tmp_state = element["state"]
                                end
                                if element.name == "service"
                                    tmp_service = element["name"]
                                end
                            end
                            data = node(tmp_port_id, tmp_protocol, tmp_state, tmp_service)
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
    originalSTDOUT = stdout;
    (outread, outwrite) = redirect_stdout()
    run(`nmap $(server) -oX tmp_$(server).xml --top-ports 20`)
    output = nmapXML_2_dict("tmp_$(server).xml")
    rm("tmp_$(server).xml")
    redirect_stdout(originalSTDOUT)
    return output
end
