
"""
By DNS returns IP address.
Example:
convert_dns2ip("fel.cvut.cz")

Tested with:
macOS Catalina v10.15.5.
"""

function convert_dns2ip(server_name::String)
    """
    Converts info about ports from XML file to dictionary.
    :param server_name: DNS (String).
    :return: IP address (String)
    """
    originalSTDOUT = stdout;
    (outread, outwrite) = redirect_stdout()
    run(`dig $(server_name) +short`)  
    output = readline(outread)
    redirect_stdout(originalSTDOUT)
    return output
end
