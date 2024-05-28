"""
API Documentation

This module provides functionalities to manage a TCP server for routing tables updates.

Classes:
    TCPServer:
        A class to handle TCP server operations.

        Methods:
            __init__(self, host: str, port: int, algorithm: str):
                Initializes the TCP server with the specified host, port, and routing algorithm.

            start(self):
                Starts the TCP server to listen for incoming connections.

            handle_client(self, client_socket: socket.socket):
                Handles the incoming client requests.

            compute_routing_tables(self):
                Computes the routing tables using the specified algorithm.

            update_routing_tables(self):
                Updates the routing tables periodically.

            remove_node(self, node_name: str):
                Removes a node from the network.

            add_node_to_network(self, node_name: str, node_id: int):
                Adds a node back to the network.

Variables:
    private_key: rsa.PrivateKey
        The private key used for decrypting messages.

    public_key: rsa.PublicKey
        The public key used for encrypting messages.

    network: Network
        An instance of the Network class representing the network topology.
"""
import socket
import threading
import json
import networkx as nx
import rsa
import pickle
import mariadb  # Importar el conector de MariaDB
import mysql.connector
from mysql.connector import Error
from network import Network

file_pri = open('pri_key.txt', 'rb')
private_key = pickle.load(file_pri)
file_pri.close()
# Load the public key from file
file_pub = open('pub_key.txt', 'rb')
public_key = pickle.load(file_pub)
file_pub.close()

network = Network()
network.add_node(1, '10.0.0.1')
network.add_node(2, '10.0.0.2')
network.add_node(3, '10.0.0.3')
network.add_node(4, '10.0.0.4')
network.add_node(5, '10.0.0.5')
network.add_node(6, '10.0.0.6')
network.add_node(7, '10.0.0.7')
network.add_node(8, '10.0.0.8')
network.add_node(9, '10.0.0.9')
network.add_node(10, '10.0.0.10')
network.add_node(11, '10.0.0.11')
network.add_node(12, '10.0.0.12')
network.add_node(13, '10.0.0.13')
network.add_node(14, '10.0.0.14')

network.add_link(1, 2, 2100)
network.add_link(1, 8, 4800)
network.add_link(1, 3, 3000)
network.add_link(2, 4, 1500)
network.add_link(2, 3, 1200)
network.add_link(3, 6, 3600)
network.add_link(4, 5, 1200)
network.add_link(4, 11, 3900)
network.add_link(5, 7, 1200)
network.add_link(5, 6, 2400)
network.add_link(6, 10, 2100)
network.add_link(6, 14, 3600)
network.add_link(7, 10, 2700)
network.add_link(7, 8, 1500)
network.add_link(8, 9, 1500)
network.add_link(9, 10, 1500)
network.add_link(9, 12, 600)
network.add_link(9, 13, 600)
network.add_link(11, 12, 1200)
network.add_link(11, 13, 1500)
network.add_link(12, 14, 600)
network.add_link(13, 14, 300)


class TCPServer:
    def __init__(self, host, port, algorithm):
        self.host = host
        self.port = port
        self.server_socket = None
        self.node_timers = {}  # Diccionario para almacenar temporizadores de nodos
        self.algorithm = algorithm

    def start(self):
        # Create a TCP server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the address and port
        self.server_socket.bind((self.host, self.port))
        # Listen for incoming connections
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}...")
        # Start a timer to update routing tables periodically
        threading.Timer(30, self.update_routing_tables).start()
        while True:
            try:
                # Accept a new connection
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection established with {client_address}")
                # Start a new thread to handle the client
                client_handler_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler_thread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def handle_client(self, client_socket):
        try:
            # Receive the encrypted node name from the client
            encrypted_node_name = client_socket.recv(1024)

            # Decrypt the node name
            node_name_bytes = rsa.decrypt(encrypted_node_name, private_key)
            node_name = node_name_bytes.decode()  # Convertir bytes a cadena

            print(f"Received request from node: {node_name}")
            # If there is an existing timer for the node, cancel it
            if node_name in self.node_timers:
                self.node_timers[node_name].cancel()
            # Start a new timer for the node
            self.node_timers[node_name] = threading.Timer(30, self.remove_node, args=(node_name,))
            self.node_timers[node_name].start()
            # Get routing table for the corresponding node from the database
            node_id = node_name[-1]
            connection = mysql.connector.connect(user='Bryan', password='', host='127.0.0.1',
                                                 database='nfsnet')
            cursor = connection.cursor()
            cursor.execute("SELECT Route FROM Router WHERE IP_Router = %s", (node_name,))
            route_data = cursor.fetchone()
            if route_data:
                route_json = route_data[0]
                client_socket.sendall(route_json.encode())
                print(f"Routing table sent to {node_name}.")
            else:
                print(f"No routing table found for node {node_name}.")
                self.add_node_to_network(node_name, node_id)
            cursor.close()
            connection.close()
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            # Close the client socket
            client_socket.close()

    def compute_routing_tables(self):
        try:
            if self.algorithm == 'dijkstra':
                all_paths = dict(nx.all_pairs_dijkstra_path(network.graph))
            elif self.algorithm == 'bellman':
                all_paths = dict(nx.all_pairs_bellman_ford_path(network.graph))
            else:
                raise ValueError("Invalid algorithm specified. Use 'dijkstra' or 'bellman_ford'.")

            connection = mysql.connector.connect(user='Bryan', password='', host='127.0.0.1', database='nfsnet')
            cursor = connection.cursor()

            for node, paths in all_paths.items():
                route = {destination: path for destination, path in paths.items()}
                route_json = json.dumps(route)
                cursor.execute("UPDATE Router SET Route = %s WHERE IP_Router = %s", (route_json, node))

            connection.commit()
            cursor.close()
            connection.close()

            print("Routing tables updated in the database.")
        except Error as e:
            print(f"Error updating routing tables: {e}")
        finally:
            threading.Timer(30, self.update_routing_tables).start()
    def update_routing_tables(self):
        threading.Thread(target=self.compute_routing_tables).start()

    def remove_node(self, node_name):
        print(f"Removing node {node_name} from topology.")
        network.remove_node(node_name)

    def add_node_to_network(self, node_name, node_id):
        print(f"Node {node_name} reconnected. Adding it back to the network.")
        network.add_node(node_id, node_name)
        network.display_network()

# Example usage
if __name__ == "__main__":
    # Start TCP server
    algorithm = input("Enter bellman or dijkstra to set your algorithm: ")
    server = TCPServer("localhost", 8000, algorithm)
    server.start()
