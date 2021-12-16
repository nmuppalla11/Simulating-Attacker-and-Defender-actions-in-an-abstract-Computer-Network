"""This module holds the necessary functions for an attacker agent
in an abstract computer network, built upon the network_data module."""
import random
from typing import Union, List, Dict
from network_data import ComputerNetwork as Network
from network_data import ComputerNode as Node
from network_data import Credential, Vulnerability, PrivilegeLevel, RulePermission, Edge
import network_data
from defender_data import Defender


# helper function to check if all the listening protocols needed for a vulnerability are present in the computer node
def check_for_protocol_match(services, listening_protocols):
    protocol_list = []
    for service in services:
        protocol_list.append(service.protocolName)
    for protocol in listening_protocols:
        if protocol not in protocol_list:
            return False
    return True


# helper function to check if the properties necessary for a vulnerability to exist, are present on the computer node
def check_for_properties_match(node_properties, vulnerability_properties) -> bool:
    for property_list in vulnerability_properties:
        if type(property_list) is str:
            if property_list not in node_properties:
                return False
        else:
            present = False
            for property_item in property_list:
                if property_item in node_properties:
                    present = True
            if not present:
                return False
    return True


# helper function that utilizes the above two functions to know if the vulnerability exists on a node or not
def check_for_vulnerability_match(node, vulnerability) -> bool:
    if vulnerability.effected_os != node.OSType:
        return False
    if not check_for_protocol_match(node.services, vulnerability.listening_protocols):
        return False
    if not check_for_properties_match(node.properties, vulnerability.properties):
        return False
    return True


# An Object of the Attacker class  will try to own the computer network by exploiting vulnerabilities on compromised
# computer nodes and gathering information about newly discovered computer nodes and using vulnerabilities to connect
# to them.
# The attributes needed for an attacker class are a list of compromised node ids, a list of discovered node ids, a list
# of node ids that are compromised and fully exploited using the available vulnerabilities, and a dictionary that
# contains the node information about compromised and discovered nodes. In addition, the attacker agents needs a string
# called target_node_id that stores the node id of current node that is being targeted by the attacker and node info of
# that target node id, a universal list of vulnerabilities, a list of credentials discovered so far, a list of
# credentials that are used in exploitations, the reward accumulated as a result of exploiting vulnerabilities,
# a ComputerNetwork object, a Defender object, and a probability value
class Attacker:
    compromised_node_ids: List[str] = []
    discovered_node_ids: List[str] = []
    explored_node_ids: List[str] = []
    node_info: Dict[str, Node] = {}
    current_node_id: str
    target_node_id: str
    vulnerability_library: List[network_data.Vulnerability] = []
    discovered_credentials: List[network_data.Credential] = []
    used_credentials: List[network_data.Credential] = []
    reward_accumulated: float = 0.0
    network: Network
    defender: Defender
    chance: float

    def __init__(self, network, defender, chance):
        self.network = network
        self.defender = defender
        self.chance = chance
        self.vulnerability_library = self.network.library.vulnerability_library
        for node_id in self.network.nodesList.keys():
            self.network.used_vulnerabilities[node_id] = []

    # retrieves node information for all the nodes that are marked as compromised
    def get_compromised_node_info(self):
        for node in self.network.nodesList.values():
            if node.compromised and node.nodeId not in self.compromised_node_ids \
                    and node.nodeId not in self.explored_node_ids:
                self.compromised_node_ids.append(node.nodeId)
                self.node_info[node.nodeId] = node
                self.current_node_id = node.nodeId
                if len(node.cached_node_ids) > 0:
                    for node_id in node.cached_node_ids:
                        self.discovered_node_ids.append(node_id)
                if len(node.cached_credentials) > 0:
                    for credential in node.cached_credentials:
                        self.discovered_credentials.append(credential)

    # retrieves partial node information about the target node
    def scan_discovered_node_info(self, node_id):
        for node in self.network.nodesList.values():
            if node.nodeId == node_id:
                new_node = Node()
                new_node.nodeId = node.nodeId
                new_node.OSType = node.OSType
                new_node.properties = node.properties
                new_node.services = node.services
                new_node.firewallRules = []
                new_node.vulnerabilities = []
                new_node.privilegeLevel = PrivilegeLevel.NO_ACCESS
                new_node.compromised = False
                self.node_info[node_id] = new_node

    # emulates the connection to a  remote node, might succeed or fail depending on some probability
    def remote_probe(self, node_id) -> bool:
        if random.random() < self.chance:
            self.scan_discovered_node_info(node_id)
            return True
        return False

    # from the universal list of vulnerabilities, this function chooses a list of vulnerabilities that might exist in a
    # given node
    def choose_vulnerabilities(self) -> List[network_data.Vulnerability]:
        matched_vulnerabilities: List[network_data.Vulnerability] = []
        for vulnerability in self.vulnerability_library:
            if check_for_vulnerability_match(self.node_info[self.target_node_id], vulnerability) and \
                    vulnerability not in self.network.used_vulnerabilities[self.target_node_id]:
                matched_vulnerabilities.append(vulnerability)
        return matched_vulnerabilities

    # given a vulnerability, list of credentials, this function tries to exploit that vulnerability on the target node
    def exploit_vulnerability(self, vulnerability: Vulnerability,
                              credential: Union[str, List[Credential]]) -> bool:
        success = False
        if check_for_vulnerability_match(self.network.nodesList[self.target_node_id], vulnerability):
            if self.network.nodesList[self.target_node_id].compromised is True and \
                    vulnerability.vulnerability_type == network_data.VulnerabilityType.LOCAL:
                success = self.privilege_escalation()
            elif vulnerability.vulnerability_type == network_data.VulnerabilityType.REMOTE and credential != "":
                success = self.lateral_move(credential)
            if success:
                self.network.used_vulnerabilities[self.target_node_id].append(vulnerability)
        return success

    # to exploit a local vulnerability, this function is called from the exploit_vulnerability() function
    # using some probability, the privilege level on the target node will be elevated to the next level
    def privilege_escalation(self) -> bool:
        if random.random() < self.chance:
            if self.network.nodesList[self.target_node_id].privilegeLevel == PrivilegeLevel.NO_ACCESS:
                self.network.nodesList[self.target_node_id].privilegeLevel = PrivilegeLevel.LOCAL_USER
                return True
            elif self.network.nodesList[self.target_node_id].privilegeLevel == PrivilegeLevel.LOCAL_USER:
                self.network.nodesList[self.target_node_id].privilegeLevel = PrivilegeLevel.ADMIN_USER
                return True
            else:
                self.network.nodesList[self.target_node_id].privilegeLevel = PrivilegeLevel.SYSTEM_LEVEL
                return True
        return False

    # to exploit a remote vulnerability, this function is called from the exploit_vulnerability() function
    # using the list of credentials provided, this function tries each credential to exploit the given vulnerability
    # on the target remote node. For the connection to succeed, in addition to the correct credential, the firewall rule
    # for the incoming protocol should allow the connection and the service that handles the incoming connection should
    # be in running state
    def lateral_move(self, credentials: List[Credential]) -> bool:
        for credential in credentials:
            incoming_firewall = self.network.nodesList[self.target_node_id].firewallRules.Incoming
            found = False
            for service in self.network.nodesList[self.target_node_id].services:
                if service.isServiceRunning and service.credential == credential:
                    found = True
            if found:
                if credential.protocolName in incoming_firewall and \
                        incoming_firewall[credential.protocolName] == RulePermission.ALLOW:
                    self.network.nodesList[self.target_node_id].compromised = True
                    self.discovered_credentials.remove(credential)
                    self.used_credentials.append(credential)
                    return True
        return False

    # If the attacker wants to perform a local attack, this method is called. The local_attack() method calls the
    # privilege_escalation() method to perform a local attack that results in privilege escalation. The local_attack()
    # method chooses a node_id and calls the privilege_escalation() method on it. The outcome of the vulnerability
    # exploitation is appropriately handled.
    def local_attack(self):
        self.get_compromised_node_info()
        while True:
            self.target_node_id = self.compromised_node_ids[random.randint(0, len(self.compromised_node_ids) - 1)]
            if self.target_node_id not in self.defender.re_imaging_nodes:
                break
        self.current_node_id = self.target_node_id
        matched_vulnerabilities = self.choose_vulnerabilities()
        for vulnerability in matched_vulnerabilities:
            if vulnerability.vulnerability_type == network_data.VulnerabilityType.LOCAL:
                success = self.exploit_vulnerability(vulnerability, "")
                if success:
                    if random.random() < 0.5:
                        vulnerability.outcome = network_data.CachedCredentials()
                        credentials_list = []
                        for credential in self.network.credentialsList:
                            if random.random() < self.chance and credential not in self.used_credentials:
                                credentials_list.append(credential)
                        vulnerability.outcome.credentials = credentials_list
                        print("Privilege Escalation on Node " + self.target_node_id +
                              " is successful using the vulnerability " + vulnerability.vulnerability_id +
                              " and the exploitation revealed a few cached credentials")
                    else:
                        vulnerability.outcome = network_data.CachedNodeID()
                        node_ids_list = []
                        for node_id in self.network.nodesList.keys():
                            if random.random() < self.chance and node_id not in self.compromised_node_ids \
                                    and node_id not in self.discovered_node_ids \
                                    and node_id not in self.explored_node_ids:
                                node_ids_list.append(node_id)
                        print("Privilege Escalation on Node " + self.target_node_id +
                              " is successful using the vulnerability " + vulnerability.vulnerability_id +
                              " and the exploitation revealed a few cached node IDs")
                        vulnerability.outcome.nodeIDs = node_ids_list
                else:
                    vulnerability.outcome = network_data.ExploitFailed()
                    print("Privilege Escalation on Node " + self.target_node_id +
                          " using the vulnerability " + vulnerability.vulnerability_id +
                          " failed.")
                if success and isinstance(vulnerability.outcome, network_data.CachedCredentials):
                    self.reward_accumulated += vulnerability.outcome.reward
                    for credential in vulnerability.outcome.credentials:
                        self.discovered_credentials.append(credential)
                    break
                elif success and isinstance(vulnerability.outcome, network_data.CachedNodeID):
                    self.reward_accumulated += vulnerability.outcome.reward
                    for nodeId in vulnerability.outcome.nodeIDs:
                        self.discovered_node_ids.append(nodeId)
                    break
                else:
                    self.reward_accumulated += vulnerability.outcome.reward
        if self.network.nodesList[self.target_node_id].privilegeLevel == PrivilegeLevel.SYSTEM_LEVEL:
            self.compromised_node_ids.remove(self.target_node_id)
            if self.target_node_id not in self.explored_node_ids:
                self.explored_node_ids.append(self.target_node_id)

    # If the attacker chooses to perform a remote attack, this method is called. This method in turn will set all the
    # necessary variables and will call the lateral_move() method. The result of the lateral_move() method is handled
    # at the end.
    def remote_attack(self):
        self.get_compromised_node_info()
        for node_id in self.discovered_node_ids:
            if self.remote_probe(node_id):
                print("Gathered information about " + node_id)
                self.reward_accumulated += 2
            else:
                self.reward_accumulated -= 2
        for _ in self.discovered_node_ids:
            node_id = random.choice(self.discovered_node_ids)
            if node_id not in self.node_info or node_id in self.defender.re_imaging_nodes:
                continue
            associated_discovered_credentials = []
            success = False
            for credential in self.discovered_credentials:
                if credential.nodeID == node_id:
                    associated_discovered_credentials.append(credential)
            if len(associated_discovered_credentials) > 0:
                self.target_node_id = node_id
                matched_vulnerabilities = self.choose_vulnerabilities()
                for vulnerability in matched_vulnerabilities:
                    if vulnerability.vulnerability_type == network_data.VulnerabilityType.REMOTE:
                        success = self.exploit_vulnerability(vulnerability, associated_discovered_credentials)
                        if success:
                            vulnerability.outcome = network_data.LateralMoveSucceeded()
                            self.discovered_node_ids.remove(node_id)
                            self.compromised_node_ids.append(node_id)
                            self.reward_accumulated += vulnerability.outcome.reward
                            print("Remote Exploitation on Node " + self.target_node_id +
                                  " is successful using the vulnerability " + vulnerability.vulnerability_id)
                            self.network.edgesList.append(Edge(self.current_node_id, self.target_node_id,
                                                               vulnerability.vulnerability_id))
                            self.current_node_id = self.target_node_id
                            break
                        else:
                            vulnerability.outcome = network_data.ExploitFailed()
                            self.reward_accumulated += vulnerability.outcome.reward
                            print("Remote Exploitation on Node " + self.target_node_id +
                                  " using the vulnerability " + vulnerability.vulnerability_id + " failed.")
            if success:
                break

    # The attacker agent in order to take a step inside the computer network, will call the attack() method.
    # Based on the current state of the network, the attack() method can perform a local attack or remote attack.
    def attack(self):
        self.get_compromised_node_info()
        if len(self.compromised_node_ids) != 0 and len(self.discovered_node_ids) == 0:
            self.local_attack()
        elif len(self.discovered_node_ids) != 0:
            self.remote_attack()
        else:
            return False
        return True
