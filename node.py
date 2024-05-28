"""
API Documentation

This class represents a network node.

Attributes:
    node_id (int): The ID of the node.
    name (str): The name of the node.
    node_type (str): The type of the node, default is 'router'.

Methods:
    __init__(node_id, name, node_type='router'):
        Initializes a Node object with the specified ID, name, and optional node type.

    __repr__():
        Returns a string representation of the Node object.
"""

class Node:
    """
    Initializes a Node object with the specified ID, name, and optional node type.

    Args:
        node_id (int): The ID of the node.
        name (str): The name of the node.
        node_type (str, optional): The type of the node (default is 'router').
    """
    def __init__(self, node_id, name, node_type='router'):
        self.node_id = node_id
        self.name = name
        self.node_type = node_type

    def __repr__(self):
        """
        Returns a string representation of the Node object.
        """

        return f"Node({self.name}, ID={self.node_id}, Type={self.node_type})"