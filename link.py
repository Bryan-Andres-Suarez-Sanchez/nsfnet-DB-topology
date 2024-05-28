"""
API Documentation

This class represents a link in a network, connecting a source node to a destination node with a specified bandwidth.

Attributes:
    source (str): The name or identifier of the source node.
    destination (str): The name or identifier of the destination node.
    bandwidth (float): The bandwidth capacity of the link in Gbps.

Methods:
    __init__(source, destination, bandwidth):
        Initializes a Link object with the provided source, destination, and bandwidth.

    __repr__():
        Returns a string representation of the Link object.
"""


class Link:
    def __init__(self, source, destination, bandwidth):
        """
               Initializes a Link object with the provided source, destination, and bandwidth.

               Args:
                   source (str): The name or identifier of the source node.
                   destination (str): The name or identifier of the destination node.
                   bandwidth (float): The bandwidth capacity of the link in Gbps.
        """
        self.source = source
        self.destination = destination
        self.bandwidth = bandwidth

    def __repr__(self):
        """
                Returns a string representation of the Link object.

                Returns:
                    str: A string representation of the Link object.
                """
        return f"Link({self.source} -> {self.destination}, Bandwidth={self.bandwidth} Gbps)"