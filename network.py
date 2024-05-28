"""
API Documentation

This class represents a network composed of nodes and links.

Attributes:
    nodes (dict): A dictionary containing the nodes in the network, where keys are node IDs and values are Node objects.
    links (list): A list containing the links in the network, where each element is a Link object.
    graph (NetworkX Graph): A NetworkX Graph object representing the network topology.

Methods:
    __init__():
        Initializes a Network object with empty nodes, links, and graph.

    add_node(node_id, name, node_type='router'):
        Adds a node to the network with the given ID, name, and optional node type.

    add_link(source_id, destination_id, bandwidth):
        Adds a link to the network between the specified source and destination nodes with the given bandwidth.

    remove_node(node_name):
        Removes the node with the specified name from the network.

    remove_link(source_id, destination_id):
        Removes the link between the specified source and destination nodes from the network.

    display_network():
        Displays information about the nodes and links in the network.

    visualize_network():
        Visualizes the network topology using matplotlib and NetworkX.
"""

import networkx as nx
import matplotlib.pyplot as plt
from node import Node
from link import Link

class Network:
    def __init__(self):
        """
                Initializes a Network object with empty nodes, links, and graph.
        """
        self.nodes = {}
        self.links = []
        self.graph = nx.Graph()

    def add_node(self, node_id, name, node_type='router'):
        """
        Adds a node to the network with the given ID, name, and optional node type.

        Args:
            node_id (int): The ID of the node.
            name (str): The name of the node.
            node_type (str, optional): The type of the node (default is 'router').
        """

        if node_id not in self.nodes:
            self.nodes[node_id] = Node(node_id, name, node_type)
            self.graph.add_node(name, node_type=node_type)

    def add_link(self, source_id, destination_id, bandwidth):
        """
        Adds a link to the network between the specified source and destination nodes with the given bandwidth.

        Args:
            source_id (int): The ID of the source node.
            destination_id (int): The ID of the destination node.
            bandwidth (float): The bandwidth capacity of the link in Gbps.
        """
        if source_id in self.nodes and destination_id in self.nodes:
            source_node = self.nodes[source_id]
            destination_node = self.nodes[destination_id]
            self.links.append(Link(source_node, destination_node, bandwidth))
            self.graph.add_edge(source_node.name, destination_node.name, weight=1/bandwidth)
        else:
            print(f"Error ({source_id} y {destination_id}) no red")

    def remove_node(self, node_name):
        """
        Removes the node with the specified name from the network.

        Args:
            node_name (str): The name of the node to be removed.
        """
        for node_id, node in self.nodes.items():
            if node.name == node_name:
                del self.nodes[node_id]
                self.graph.remove_node(node_name)
                self.links = [link for link in self.links if
                              link.source.name != node_name and link.destination.name != node_name]
                return
        print(f"Error: Node with name {node_name} not found")

    def remove_link(self, source_id, destination_id):
        """
        Removes the link between the specified source and destination nodes from the network.

        Args:
            source_id (int): The ID of the source node.
            destination_id (int): The ID of the destination node.
        """
        if source_id in self.nodes and destination_id in self.nodes:
            self.graph.remove_edge(self.nodes[source_id].name, self.nodes[destination_id].name)
            self.links = [link for link in self.links if
                          link.source != self.nodes[source_id] or link.destination != self.nodes[destination_id]]
        else:
            print("Error: Source or destination node not found")

    def display_network(self):
        """Displays information about the nodes and links in the network."""

        print("Nodes in the network:")
        for node in self.nodes.values():
            print(node)
        print("\nLinks in the network:")
        for link in self.links:
            print(link)

    def visualize_network(self):
        """Visualizes the network topology using matplotlib and NetworkX."""

        pos = nx.spring_layout(self.graph)  # posiciones para todos los nodos
        nx.draw(self.graph, pos, with_labels=True, node_size=2000, node_color="skyblue", font_size=10,
                font_weight="bold")
        labels = nx.get_edge_attributes(self.graph, 'weight')
        nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=labels, font_size=7)
        plt.show()


