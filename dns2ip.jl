
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
    println("X")
    output = "X"
    while isIPv4(output) != true || isIPv6(output) != true || output != ""
        output = readline(outread)
        if output == "X"
            output = ""
            break
        else
            if occursin(".", output)
                if isIPv4(output) == true
                    break
                end
            elseif occursin(":", output)
                if isIPv6(output) == true
                    break
                end 
            end
        end
    end
    redirect_stdout(originalSTDOUT)
    return output
end

function isIPv4(address::String)
    str = split(address, ".")
    for s in str
        try
            string(parse(Int, s)) == s && 0 <= parse(Int, s) <= 255
        catch
            return false
        end
    end
    return true
end

function isIPv6(address::String)
    str = split(address, ":")
    for s in str
        if length(s) > 4
            return false
        end
        try
            length(s) >= 0 && s[1] != '-'
        catch
            return false
        end
    end
    return true
end
