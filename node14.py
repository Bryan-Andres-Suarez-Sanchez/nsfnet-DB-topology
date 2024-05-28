"""
API Documentation

This class represents a TCP node in a network.

Attributes:
    node_name (str): The name of the node.
    server_host (str): The hostname of the server.
    server_port (int): The port of the server.
    listen_port (int): The port on which the node listens for incoming connections.
    outgoing_ports (list): List of outgoing ports for connecting to other nodes.
    routing_table (dict): Dictionary representing the routing table of the node.
    client_port (int): The port for connecting to the client.

Methods:
    __init__(node_name, server_host, server_port, listen_port, outgoing_ports):
        Initializes a TCPNode object with the specified parameters.

    start():
        Starts the node by initializing the server for incoming connections,
        connecting to the server to obtain the routing table, and
        listening for incoming connections from other nodes.

    stop():
        Stops the node by closing the server socket.

    connect_to_server():
        Connects to the server to obtain the routing table.

    accept_connections():
        Accepts incoming connections from other nodes in a separate thread.

    handle_client(client_socket):
        Handles a client connection by receiving and processing messages.

    connect_to_node(destination_node_name, position, message):
        Connects to a destination node and sends a message.

    handle_user_message(message_type, origin_node, destination_node, user_message):
        Handles a user message by printing it and routing it to the destination node.

    route_message(destination_node_name, message):
        Routes a message to the destination node based on the routing table.

"""
import socket
import json
import threading
import time
import pickle
import rsa

file_pri = open('pri_key.txt', 'rb')
private_key = pickle.load(file_pri)
file_pri.close()
# Load the public key from file
file_pub = open('pub_key.txt', 'rb')
public_key = pickle.load(file_pub)
file_pub.close()

class TCPNode:
    def __init__(self, node_name, server_host, server_port, listen_port, outgoing_ports):
        """
        Initializes a TCPNode instance.

        Args:
            node_name (str): The name of the node.
            server_host (str): The host address of the server.
            server_port (int): The port number of the server.
            listen_port (int): The port number to listen on for incoming connections.
            outgoing_ports (list): A list of outgoing port numbers.
        """
        self.node_name = node_name
        self.server_host = server_host
        self.server_port = server_port
        self.listen_port = listen_port
        self.outgoing_ports = outgoing_ports
        self.routing_table = None
        self.client_port = client_port
        with open("port_mapping.json", "r") as file:
            self.port_mapping = json.load(file)

    def start(self):
        """
        Starts the node by initiating the server socket and connecting to the server.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("localhost", self.listen_port))
        self.server_socket.listen(5)
        print(f"Node {self.node_name} listening on port {self.listen_port}...")

        self.connect_to_server()

        threading.Thread(target=self.accept_connections).start()

    def stop(self):
        """
        Stops the node by closing the server socket.
        """

        self.server_socket.close()

    def connect_to_server(self):
        """
        Connects to the server to obtain the routing table.
        """

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_host, self.server_port))
            encrypted_node_name = rsa.encrypt(self.node_name.encode(), public_key)
            client_socket.sendall(encrypted_node_name)
            routing_table_json = client_socket.recv(4096).decode()
            self.routing_table = json.loads(routing_table_json)
            client_socket.close()
            print(f"ACK received from controller :", self.routing_table)
        except Exception as e:
            print(f"Error while connecting to server: {e}")

    def accept_connections(self):
        """
        Accepts incoming connections from other nodes.
        """

        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Node {self.node_name} accepted connection from {client_address}")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def handle_client(self, client_socket):
        """
        Handles incoming messages from clients.

        Args:
            client_socket (socket.socket): The socket object representing the client connection.
        """
        try:
            data = client_socket.recv(1024)
            message_data = pickle.loads(data)
            message_type = message_data.get("tipo")
            origin_node = message_data.get("origen")
            destination_node = message_data.get("destino")
            user_message = message_data.get("mensaje")

            self.handle_user_message(message_type, origin_node, destination_node, user_message)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def connect_to_node(self, destination_node_name, position, message):
        """
        Connects to a destination node and sends a message.

        Args:
            destination_node_name (str): The name of the destination node.
            position (int): The position in the outgoing_ports list.
            message (str): The message to send.
        """
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("localhost", self.outgoing_ports[position]))
            client_socket.sendall(destination_node_name.encode())
            print(f"Node {self.node_name} connected to {destination_node_name} on port {self.outgoing_ports[position]}")
            client_socket.sendall(message.encode())
            client_socket.close()
        except Exception as e:
            print(f"Error while connecting to node {destination_node_name} on port {self.outgoing_ports[position]}: {e}")

    def handle_user_message(self, message_type, origin_node, destination_node, user_message):
        """
        Handles user messages.

        Args:
            message_type (str): The type of message.
            origin_node (str): The origin node of the message.
            destination_node (str): The destination node of the message.
            user_message (str): The user message.
        """
        print(f"Received user message from {origin_node} to {destination_node}: {user_message}")

        self.route_message(destination_node, {
            "tipo": message_type,
            "origen": origin_node,
            "destino": destination_node,
            "mensaje": user_message
        })

    def route_message(self, destination_node_name, message):
        """
        Routes a message to a destination node.

        Args:
            destination_node_name (str): The name of the destination node.
            message (dict): The message to route.
        """
        if destination_node_name in self.routing_table:

            path_to_destination = self.routing_table[destination_node_name]

            if len(path_to_destination) > 1:

                next_hop = path_to_destination[1]

                next_hop_port = self.port_mapping[next_hop]

                if next_hop_port is not None:

                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect(("localhost", next_hop_port))


                    client_socket.sendall(pickle.dumps(message))

                    print(f"Node {self.node_name} routed message to {destination_node_name} via {next_hop}")


                    #client_socket.close()
                else:
                    print(f"No outgoing port found for next hop {next_hop}.")
            else:
                # Si el nodo actual es el nodo destino, enviar el mensaje de vuelta al cliente receptor
                print(f"Node {self.node_name} is the destination node. Sending message back to client.")
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect(("localhost", client_port))
                client_socket.sendall(pickle.dumps(message))
                client_socket.close()
        else:
            print(f"No route found to {destination_node_name}")

# Example of use
if __name__ == "__main__":
    node_name = "10.0.0.14"
    server_host = "localhost"
    client_port = 7014
    server_port = 8000
    listen_port = 9024
    outgoing_ports = [9011, 9012, 9014]
    node = TCPNode(node_name, server_host, server_port, listen_port, outgoing_ports)
    node.start()

    while True:
        node.connect_to_server()
        time.sleep(15)

