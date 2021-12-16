"""This module houses Defender Class. A defender agent will try to defend the abstract network from the attacker."""
import random
from network_data import ComputerNetwork as Network
from typing import List, Dict


# The Defender class contains a Network object passed from the network_data module and it contains the information about
# the abstract network. In addition, it also has a scan capacity which indicates the number of nodes the defender can
# scan at a time, a list of all the node IDs in the network, another list to keep track of the nodes that are being
# re-imaged and chance, a probability that controls the change of configurations for recovered nodes.
class Defender:
    network: Network
    scan_capacity: int
    node_ids: List[str] = []
    chance: float
    re_imaging_nodes: Dict[str, int] = dict()

    # Initializer method for the Defender Class. It assigns the scan capacity and network attributes with values passed
    # during creation of the object. It also initializes the list of node ids by extracting the node IDS from the
    # nodesList dictionary in the network object.
    def __init__(self, scan_capacity, network, chance):
        self.network = network
        self.scan_capacity = scan_capacity
        self.node_ids = list(self.network.nodesList.keys())
        self.chance = chance

    # This method is called by the defend method to scan some nodes in the network and re-image the nodes if they
    # are compromised. Re-imaging a node is completed after five defender steps. This method goes through all the nodes
    # that are in the process of re-imaging and decrements the step counter of respective nodes by 1. If any of the
    # nodes have reached the counter value of zero i.e., endured the five defender steps, are marked as not compromised
    # and their configuration is changed at random to avoid being compromised again in the future.
    # After monitoring the re-imaging process, some nodes are chosen at random and the compromised nodes among
    # them are marked to be re-imaged by adding them to the re-imaging nodes list.
    def scan_and_re_image(self):
        nodes_to_be_popped = []
        for node_id in self.re_imaging_nodes:
            self.re_imaging_nodes[node_id] -= 1
            if self.re_imaging_nodes[node_id] == 0:
                nodes_to_be_popped.append(node_id)
                self.network.nodesList[node_id].compromised = False
                self.change_configuration(node_id)
        scanned_node_ids = random.sample(self.node_ids, self.scan_capacity)
        for node_id in nodes_to_be_popped:
            self.re_imaging_nodes.pop(node_id)
            print("Node " + node_id + " is completely re-imaged.")
            self.network.used_vulnerabilities[node_id] = []
        for node_id in scanned_node_ids:
            if random.random() < self.chance and self.network.nodesList[node_id].compromised and\
                    node_id not in self.re_imaging_nodes:
                self.re_imaging_nodes[node_id] = 5
                print("Node " + node_id + " is identified to be compromised and is marked for re-imaging. "
                                          "Re-imaging will take five steps to complete.")

    # This method is called by the scan_and_re_image() method. This method goes through all the services in the node
    # and randomly stops some nodes from running and also alters respective firewall rules to deny any future
    # connections on those ports.
    def change_configuration(self, node_id):
        for service in self.network.nodesList[node_id].services:
            if service.isServiceRunning and random.random() < self.chance:
                service.isServiceRunning = False
                if service.protocolName in self.network.nodesList[node_id].firewallRules.Incoming:
                    self.network.nodesList[node_id].firewallRules.Incoming[service.protocolName] = 0
                if service.protocolName in self.network.nodesList[node_id].firewallRules.Outgoing:
                    self.network.nodesList[node_id].firewallRules.Outgoing[service.protocolName] = 0

    # Each time the defender agent is given a chance to run, it calls this defend() method to scan for compromised nodes
    # and re-image them if necessary.
    def defend(self):
        self.scan_and_re_image()
