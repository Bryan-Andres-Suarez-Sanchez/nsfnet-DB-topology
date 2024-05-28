import networkx as nx
import matplotlib.pyplot as plt
from network import Network

def find_path_bellman_ford(self, start_node_name, end_node_name):
    """
       Finds the shortest path between two nodes using the Bellman-Ford algorithm.

       Args:
           network (Network): The network instance representing the network topology.
           start_node_name (str): The name of the starting node.
           end_node_name (str): The name of the ending node.

       Returns:
           list or None: A list of node names representing the shortest path from start_node_name to end_node_name,
                         or None if no path exists.
       """

    # Initialize distances and predecessors
    distances = {node: float('inf') for node in self.graph.nodes()}
    predecessors = {node: None for node in self.graph.nodes()}
    distances[start_node_name] = 0

    # Relax edges up to V-1 times (V is the number of vertices)
    for _ in range(len(self.graph.nodes) - 1):
        for u, v, data in self.graph.edges(data=True):
            weight = data['weight']
            if distances[u] + weight < distances[v]:
                distances[v] = distances[u] + weight
                predecessors[v] = u

    # Check for negative weight cycles
    for u, v, data in self.graph.edges(data=True):
        if distances[u] + data['weight'] < distances[v]:
            print("Graph contains negative weight cycle")
            return None

    # Reconstruct the path
    path = []
    step = end_node_name
    if distances[end_node_name] == float('inf'):
        print(f"No path exists from {start_node_name} to {end_node_name}")
        return None
    while step is not None:
        path.append(step)
        step = predecessors[step]
    path.reverse()

    return path

def compute_shortest_paths_bellman_ford(network):
    """
       Computes all shortest paths in the network using the Bellman-Ford algorithm.

       Args:
           network (Network): The network instance representing the network topology.

       Returns:
           dict or None: A dictionary containing the shortest paths from each node to all other nodes,
                         or None if the graph contains a negative weight cycle.
       """
    # We initialize the results dictionary
    shortest_paths = {}

    # We iterate over all nodes as source nodes
    for source_node in network.nodes.values():
        # We initialize the dictionary to store the shortest paths from the source node
        source_paths = {}

        # We initialize the distances and predecessors
        distances = {node.name: float('inf') for node in network.nodes.values()}
        predecessors = {node.name: None for node in network.nodes.values()}

        # We set the distance from the source node to 0
        distances[source_node.name] = 0

        # We relax the edges up to V-1 times
        for _ in range(len(network.nodes) - 1):
            for u, v, data in network.graph.edges(data=True):
                weight = data['weight']
                if distances[u] != float('inf') and distances[u] + weight < distances[v]:
                    distances[v] = distances[u] + weight
                    predecessors[v] = u

                # Also consider the opposite direction of the link
                if distances[v] != float('inf') and distances[v] + weight < distances[u]:
                    distances[u] = distances[v] + weight
                    predecessors[u] = v

        # We check negative weight cycles
        for u, v, data in network.graph.edges(data=True):
            if distances[u] != float('inf') and distances[u] + data['weight'] < distances[v]:
                print("El grafo contiene un ciclo de peso negativo")
                return None

        # We build the shortest paths from the source node to the other nodes
        for target_node in network.nodes.values():
            if source_node.name == target_node.name:
                source_paths[target_node.name] = [source_node.name]
                # The source node has a path to itself
            else:
                path = []
                step = target_node.name
                while step is not None:
                    path.append(step)
                    step = predecessors[step]
                path.reverse()
                if path[0] == source_node.name:
                    source_paths[target_node.name] = path
                else:
                    # Cannot reach destination from origin
                    source_paths[target_node.name] = None

        # Add the shortest paths from the source node to the result dictionary
        shortest_paths[source_node.name] = source_paths

    return shortest_paths


def find_shortest_path_dijks(network, source_name, destination_name, weight='weight'):
    """
       Finds the shortest path between two nodes using Dijkstra's algorithm.

       Args:
           network (Network): The network instance representing the network topology.
           source_name (str): The name of the source node.
           destination_name (str): The name of the destination node.
           weight (str, optional): The name of the edge attribute to use as the weight. Default is 'weight'.

       Returns:
           list or None: A list of node names representing the shortest path from source_name to destination_name,
                         or None if no path exists.
       """
    try:
        path = nx.dijkstra_path(network.graph, source=source_name, target=destination_name, weight=weight)
        print(f"Shortest path from {source_name} to {destination_name}: {path}")
        return path
    except nx.NetworkXNoPath:
        print(f"No path exists between {source_name} and {destination_name}.")
        return None
    except KeyError as e:
        print(f"Node {e} not found in the network.")
        return None

def compute_all_shortest_paths(network):
    """
    Computes all shortest paths between all pairs of nodes in the network using Dijkstra's algorithm.

    Args:
        network (Network): The network instance representing the network topology.
    """

    all_paths = dict(nx.all_pairs_dijkstra_path(network.graph))
    for source, destinations in all_paths.items():
        for destination, path in destinations.items():
            print(f"Shortest path from {source} to {destination}: {path}")

def visualize_path(path, network):
    """
    Visualizes a path in the network graph.

    Args:
        path (list): A list of node names representing the path.
        network (Network): The network instance representing the network topology.
    """
    pos = nx.spring_layout(network.graph)
    nx.draw(network.graph, pos, with_labels=True, node_color='lightblue', node_size=500, font_size=10, font_weight='bold')
    path_edges = list(zip(path, path[1:]))
    nx.draw_networkx_nodes(network.graph, pos, nodelist=path, node_color='red')
    nx.draw_networkx_edges(network.graph, pos, edgelist=path_edges, edge_color='red', width=2)
    plt.show()


