
using JSON
using LightGraphs
using Cairo
using Compose
using GraphPlot


graph = nothing
vertices_names = nothing
network_dict = Dict()

function load_arrange_JSON(network::String)
    """
    Load and arrange information from JSON relational database (e. g. "elmag.fel.cvut.cz.json").
    :param network: relational database.
    """

    global network_dict, graph, vertices_names
    open("$(network)", "r") do f
        dicttxt = read(f, String)
        network_dict = JSON.parse(dicttxt)
    end
    for (i, key) in enumerate(keys(network_dict))
        network_dict[key] = [network_dict[key]["neighbours"], i]
    end
    graph = DiGraph(length(network_dict))
    vertices_names = collect(keys(network_dict))
end

function edges_from_vertex(vertex::String)
    """
    Extract edges from given vertex.
    :param vertex: vertex name.
    :return: array of edges in form of numbered vertices.
    """
    neighbours = network_dict[vertex][1]
    vertex_no = network_dict[vertex][2]
    edges_arr = []
    for neighbour in neighbours
        append!(edges_arr, [(vertex_no, network_dict[neighbour][2])])
    end
    return edges_arr
end

function add_vertex2graph(vertex::String)
    """
    Add vertex to graph in meaning of vertex, its neighbours and edges between them.
    :param vertex: name of vertex.
    """
    global graph, vertices_names
    edges = edges_from_vertex(vertex)
    for edge in edges
        add_edge!(graph, edge[1], edge[2])
    end
end

function create_graph(name::String)
    """
    Create complete (PDF) graph.
    :param vertex: vertex name.
    :param name: output PDF name.
    """
    for vertex in vertices_names
        add_vertex2graph(vertex)
    end
    p = gplot(graph, nodelabel=vertices_names)
    n = length(vertices_names)
    draw(PDF("$(name).pdf", (n*6)cm, (n*6)cm), p)
    run(`open $(name).pdf`)
end
