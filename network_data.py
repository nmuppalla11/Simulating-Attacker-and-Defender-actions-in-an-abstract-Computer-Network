"""This module holds the network data model and its associated classes of an abstract computer network."""
import random
import string
from dataclasses import dataclass
from typing import Union, List, Dict, Tuple


# Data class to hold the types of vulnerabilities
@dataclass
class VulnerabilityType:
    LOCAL = 0
    REMOTE = 1


# Data class that comprises the two choices for a firewall rule's permission
@dataclass
class RulePermission:
    DENY = 0
    ALLOW = 1


# Data class to represent the current privilege level on the computer node
@dataclass
class PrivilegeLevel:
    NO_ACCESS = 0
    LOCAL_USER = 1
    ADMIN_USER = 2
    SYSTEM_LEVEL = 3


# A Credential class object is associated to a particular protocol running on a specific node
class Credential:
    nodeID: str
    protocolName: str
    credential: str

    def __init__(self, node_id: str, protocol_name: str, credential: str):
        self.nodeID = node_id
        self.protocolName = protocol_name
        self.credential = credential


# Base class for the "vulnerability outcome" objects
class VulnerabilityOutcome:
    reward: float


# If the attacker fails in exploiting a vulnerability,
# an ExploitFailed object will be returned that has a negative reward
class ExploitFailed(VulnerabilityOutcome):
    reward = -10


# If the attacker's move to another node is succeeded,
# a LateralMoveSucceeded object will be returned that has a positive reward
class LateralMoveSucceeded(VulnerabilityOutcome):
    reward = 10


# If the attacker's attempt to raise privilege level succeeds,
# a PrivilegeEscalationSucceeded object will be returned that has a positive reward
class PrivilegeEscalationSucceeded(VulnerabilityOutcome):
    reward = 5


# When the Privilege escalation attempt succeeds, along with a positive reward,
# cached credentials may be returned which the attacker can use to their advantage
class CachedCredentials(PrivilegeEscalationSucceeded):
    credentials: List[Credential]


# When the privilege escalation attempt succeeds, in addition to positive reward,
# the attacker may be given the information about other nodes in the network through CachedNodID object
class CachedNodeID(PrivilegeEscalationSucceeded):
    nodeIDs: List[str]


# A Service object denotes a service running on a computer node.
# The service running will be associated with particular protocol
# and needs a Credential object to initiate a connection to the service
class Service:
    protocolName: str
    isServiceRunning: bool
    credential: Credential

    def __init__(self, protocol, is_service_running, credential):
        self.protocolName = protocol
        self.isServiceRunning = is_service_running
        self.credential = credential


# A Vulnerability object has an id associated with it along with the vulnerability type,
# outcome of the vulnerability, specific operating system on which the vulnerability is present
# and the prerequisite properties and protocols that should be present on the computer node
# for the vulnerability to be exploited successfully.
class Vulnerability:
    vulnerability_id: str
    vulnerability_type: VulnerabilityType
    outcome: VulnerabilityOutcome
    properties: List[Union[str, List[str]]]
    listening_protocols: List[str]
    effected_os: str

    def __init__(self, vulnerability_id, vulnerability_type, vulnerability_outcome, properties, protocols, os) -> None:
        self.vulnerability_id = vulnerability_id
        self.vulnerability_type = vulnerability_type
        self.vulnerability_outcome = vulnerability_outcome
        self.properties = properties
        self.listening_protocols = protocols
        self.effected_os = os


# Library object will hold data such as different operating systems, properties, protocols
# and vulnerabilities that are defined universally and can be randomly assigned to the nodes
# in the abstract network
class Library:
    os_library: List[str]
    property_library: List[str]
    protocol_library: List[str]
    vulnerability_library: List[Vulnerability]
    os_vulnerability_library: Dict[str, float]

    def __init__(self, os, properties, protocols, vulnerabilities, probabilities):
        self.os_library = os
        self.property_library = properties
        self.protocol_library = protocols
        self.vulnerability_library = vulnerabilities
        self.os_vulnerability_library = probabilities


# FirewallRules Object contains both incoming and outgoing firewall rules associated with
# a computer node
class FirewallRules:
    Incoming: Dict[str, int] = {}
    Outgoing: Dict[str, int] = {}


# A ComputerNode object resembles the computer in a real computer network. It contains features and properties such as
# node's ID, type of Operating System, services running, firewall rules assigned, vulnerabilities in the computer,
# other properties, privilege level of the logged-in user,
# bool value indicating whether the computer is compromised or not
class ComputerNode:
    nodeId: str
    OSType: str
    properties: List[str] = []
    services: List[Service] = []
    firewallRules: FirewallRules
    vulnerabilities: List[Vulnerability] = []
    privilegeLevel: PrivilegeLevel
    compromised: bool
    cached_credentials: List[Credential] = []
    cached_node_ids: List[str] = []


# prints the node data such as os type, properties, firewall rules and services
def print_node_data(node):
    print()
    print("NodeID: " + node.nodeId)
    print("OS: " + node.OSType)
    print("Properties:", end="")
    for property_item in node.properties:
        print(" " + property_item, end=" ")
    print("\nServices: ")
    for service in node.services:
        print("\t" + service.protocolName + ", " + str(service.isServiceRunning) + ", " + service.credential.credential)
    print("Incoming Firewall Rules: ", end=" ")
    for port in node.firewallRules.Incoming.keys():
        print(port + ": " + str(node.firewallRules.Incoming[port]), end="\t")
    print("\nOutgoing Firewall Rules: ", end=" ")
    for port in node.firewallRules.Outgoing.keys():
        print(port + ": " + str(node.firewallRules.Outgoing[port]), end="\t")
    print("\nVulnerabilities: ")
    for vulnerability in node.vulnerabilities:
        print("\t" + vulnerability.vulnerability_id + ", " + str(vulnerability.vulnerability_type))
    print("Privilege Level: " + str(node.privilegeLevel))
    print("Compromised: " + str(node.compromised)+"\n")


# An Edge object indicates a connection between two computer nodes and is associated with a particular remote
# vulnerability
class Edge:
    firstNodeId: str
    secondNodeId: str
    vulnerability_id: str

    def __init__(self, first_node_id: str, second_node_id: str, vulnerability_id: str):
        self.firstNodeId = first_node_id
        self.secondNodeId = second_node_id
        self.vulnerability_id = vulnerability_id


# This function takes a node id, protocol name and generates a random credential
# Using the above three values, it creates a Credential object and returns it
def create_random_credential(node_id: str, protocol_name: str):
    lower_case_alphabets = string.ascii_lowercase
    credential = "".join(random.choice(lower_case_alphabets) for _ in range(10))
    return Credential(node_id, protocol_name, credential)


# This function takes a universal property library and a list of vulnerabilities specific to a computer node
# It then assigns the prerequisite properties in the vulnerabilities to that computer node
# and will also assign some other random properties form the property library with some probability
def create_random_properties(property_library: List[Union[str, List[str]]],
                             assigned_vulnerabilities: List[Vulnerability], chance) -> List[str]:
    property_list: List[str] = []
    for vulnerability in assigned_vulnerabilities:
        for property_value in vulnerability.properties:
            if type(property_value) is str:
                property_list.append(property_value)
            else:
                property_list.append(random.choice(property_value))
    for property_value in property_library:
        if property_value not in property_list and random.random() < chance:
            property_list.append(property_value)
    return property_list


# This function takes the node id of a computer and the universal protocol library and
# a list of vulnerabilities specific to a computer node. It then extracts the prerequisite protocols from the
# vulnerabilities, creates running services for those protocols and assigns those services to the computer node.
# It will also assign some other random services to the node with some probability.
# Finally, it will generate incoming and outgoing firewall rules related to the services running on the node.
# Those rules have the permission ALLOW while rules related to other services are DENY implicitly
def create_random_services_and_firewall_rules(node_id: str, protocol_library: List[str],
                                              assigned_vulnerabilities: List[Vulnerability],
                                              chance) -> Tuple[List[Service], FirewallRules]:
    services: List[Service] = []
    firewall_rules = FirewallRules()
    assigned_protocols = []
    firewall_assigned_services = []
    for vulnerability in assigned_vulnerabilities:
        for protocol in vulnerability.listening_protocols:
            services_list = create_service(node_id, protocol, assigned_protocols)
            for service_item in services_list:
                services.append(service_item)
                assigned_protocols.append(service_item.protocolName)
    for service in services:
        firewall_rules.Incoming[service.protocolName] = RulePermission.ALLOW
        firewall_rules.Outgoing[service.protocolName] = RulePermission.ALLOW
        firewall_assigned_services.append(service)
    for protocol in protocol_library:
        if random.random() < chance:
            services_list = create_service(node_id, protocol, assigned_protocols)
            for service_item in services_list:
                services.append(service_item)
                assigned_protocols.append(service_item.protocolName)
    for service in services:
        if service not in firewall_assigned_services and random.random() < chance:
            firewall_rules.Incoming[service.protocolName] = RulePermission.ALLOW
            firewall_rules.Outgoing[service.protocolName] = RulePermission.ALLOW
    return services, firewall_rules


# The create_random_services_and_firewall_rules() function delegates the creation of services to this function. It will
# generate a credential and creates a service
def create_service(node_id, protocol, assigned_protocols):
    services_list = []
    if type(protocol) is str:
        if protocol not in assigned_protocols:
            credential = create_random_credential(node_id, protocol)
            services_list.append(Service(protocol, True, credential))
    else:
        for protocol_item in protocol:
            if protocol_item not in assigned_protocols:
                credential = create_random_credential(node_id, protocol_item)
                services_list.append(Service(protocol_item, True, credential))
    return services_list


# This function takes the operating system name and a universal list of vulnerabilities
# Depending upon the OS type, some vulnerabilities are chosen at random and assigned to the computer node
def assign_random_vulnerabilities(os_type: str, vulnerability_library: List[Vulnerability], library: Library) \
        -> List[Vulnerability]:
    vulnerability_list = []
    for vulnerability in vulnerability_library:
        if vulnerability.effected_os == os_type and\
                random.random() < library.os_vulnerability_library.get(vulnerability.effected_os):
            vulnerability_list.append(vulnerability)
    return vulnerability_list


# ComputerNetwork object consists of a nodes list that holds all the computer nodes information and edges list that
# holds the remote connections between nodes, a credentials list that holds all the credentials along with the
# library object
class ComputerNetwork:
    nodesList: Dict[str, ComputerNode] = dict()
    edgesList: List[Edge] = []
    credentialsList: List[Credential] = []
    library: Library
    num_nodes: int
    chance: float
    used_vulnerabilities: Dict[str, List[Vulnerability]] = dict()

    def __init__(self, num_nodes, library, chance):
        self.num_nodes = num_nodes
        self.library = library
        self.chance = chance

    # This function takes the number of desired nodes in a network and a universal library of values and
    # calls other helper function to create nodes with random configurations
    def generate_network(self):
        self.create_nodes()
        self.compromise_random_node_as_entrypoint()

    # This function will create nodes with random properties, vulnerabilities, services and firewall rules
    def create_nodes(self):
        for num in range(self.num_nodes):
            node = ComputerNode()
            node.nodeId = str(num)
            node.OSType = random.choice(self.library.os_library)
            assigned_vulnerabilities = assign_random_vulnerabilities(node.OSType, self.library.vulnerability_library,
                                                                     self.library)
            node.vulnerabilities = assigned_vulnerabilities
            node.properties = create_random_properties(self.library.property_library, assigned_vulnerabilities,
                                                       self.chance)
            node.services, node.firewallRules = create_random_services_and_firewall_rules(
                node.nodeId, self.library.protocol_library, assigned_vulnerabilities, self.chance)
            node.privilegeLevel = PrivilegeLevel.NO_ACCESS
            node.compromised = False
            self.nodesList[node.nodeId] = node
            for service in node.services:
                self.credentialsList.append(service.credential)
            print_node_data(node)

    # we are assuming the attacker agent somehow penetrates the network
    # so, we need to make one of the computer nodes compromised initially and assign to it some cached credentials and
    # some cached node ids
    def compromise_random_node_as_entrypoint(self):
        random_node_id = str(random.randint(0, len(self.nodesList) - 1))
        self.nodesList[random_node_id].compromised = True
        print("Node " + random_node_id + " is compromised initially")
        for node_id in self.nodesList.keys():
            if random.random() < self.chance and node_id != random_node_id:
                self.nodesList[random_node_id].cached_node_ids.append(node_id)
        for credential in self.credentialsList:
            if random.random() < self.chance:
                self.nodesList[random_node_id].cached_credentials.append(credential)
