"""This module hosts the main function that binds everything together to create an abstract network and creates
attacker and defender objects that act on the network."""
from network_data import Vulnerability, VulnerabilityType, Library, VulnerabilityOutcome, ComputerNetwork
from network_data import PrivilegeLevel
from defender_data import Defender
from attacker_data import Attacker
from typing import List
import networkx
import matplotlib.pyplot as plt


# This function creates a Library Object and returns it. It has a predefined library of vulnerabilities.
def generate_library():
    vulnerability_library: List[Vulnerability] = [
        # CVE-2014-4114
        Vulnerability('sand-worm', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['MacrosEnabled', 'PackagerDLLVersion6.3'], ['SlMB'], 'Win7'),
        # CVE-2019-0708
        Vulnerability('blue-keep', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['NetworkLevelAuthenticationOff'], ['RDP'], 'Win7'),
        # CVE-2017-0143
        Vulnerability('eternal-blue', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['SMBVersion1.0'], ['SMB'], 'Win7'),
        # CVE-2010-0232
        Vulnerability('WindowsKernelExceptionHandlerVulnerability', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['NTVDMEnabled'], [], 'Win7'),
        # CVE-2015-0016
        Vulnerability('DirectoryTraversalVulnerability', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['TSWebProxyEnabled'], [], 'Win7'),
        # CVE-2015-2461
        Vulnerability('AdobeTypeManagerPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['ATMFD.DLLEnabled'], [], 'Win7'),
        # CVE-2013-3907
        Vulnerability('PortClassDriverDoubleFetchVulnerability', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['portcls.sys6.0'], [], 'Win7'),

        # CVE-2019-0726
        Vulnerability('DHCPRemoteCodeExploit', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['MaliciousDomainSearchOptionExists'], ['DHCP'], 'Win10'),
        # CVE-2017-0143
        Vulnerability('eternal-blue', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['SMBVersion1.0'], ['SMB'], 'Win10'),
        # CVE-2021-28476
        Vulnerability('HyperVRemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['HyperVEnabled', 'PermissionToRunMaliciousAppOnGuestVirtualMachine'], ['RDP'], 'Win10'),
        # CVE-2018-8178
        Vulnerability('IE11RemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['InternetExplorer11.06'], ['HTTP'], 'Win10'),
        # CVE-2021-40449
        Vulnerability('Win32kElevationOfPrivilege', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['OutOfDateGraphicsComponentOfKernelDriver', 'PermissionToRunMaliciousApplication'], [],
                      'Win10'),
        # CVE-2015-6126
        Vulnerability('PragmaticGeneralMulticastPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['MicrosoftMessageQueueingEnabled'], [], 'Win10'),
        # CVE-2015-2507
        Vulnerability('AdobeTypeManagerPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['ATMFD.DLLEnabled'], [], 'Win10'),


        # CVE-2019-11043
        Vulnerability('PHPMisConfiguration', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['PHP7.1.30', 'PHP-FPMEnabled'], ['SSH', 'FCGI'], 'Ubuntu16.04Server'),
        # CVE-2016-9775
        Vulnerability('Tomcat8CatalinaAttack', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['Tomcat8.0.5', 'PermissionToRunSetgid'], [], 'Ubuntu16.04Server'),
        # CVE-2018-8788
        Vulnerability('FreeRDPMemoryCorruption', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['FreeRDP2.0.0-rc4'], ['RDP', 'SSH'], 'Ubuntu16.04Server'),
        # CVE-2018-16509
        Vulnerability('GhostScriptAttack', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['ArtifexGhostScript9.23'], ['SCP', 'SSH'], 'Ubuntu16.04Server'),
        # CVE-2018-17456
        Vulnerability('GitRemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['GitVersion2.16.5', 'MaliciousURLFieldInGitModulesFile'], ['SSH', 'GIT'], 'Ubuntu16.04Server'),
        # CVE-2020-11884
        Vulnerability('UAccessConcurrentPageTableUpgradeError', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['LinuxKernel5.0', 'PermissionToRunCodeInEnable_sacf_uaccess'], [], 'Ubuntu16.04Server'),
        # CVE-2017-14177
        Vulnerability('ImproperCoreDumpHandlingVulnerability', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['Apport2.19'], [], 'Ubuntu16.04Server'),

        # CVE-2021-36770
        Vulnerability('EncodePerlPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['Perl5.34.0', 'Encode.pm3.11'], [], 'Fedora33Server'),
        # CVE-2021-23240
        Vulnerability('SELinuxPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['SELinuxEnabled', 'SudoVersion1.9.4'], [], 'Fedora33Server'),
        # CVE-2020-9498
        Vulnerability('GuacamoleRDPRemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['ApacheGuacamole1.1.0', 'GuacdProcessRunning'], ['RDP'], 'Fedora33Server'),
        # CVE-2020-15811
        Vulnerability('SquidRequestSplittingError', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['Squid4.12'], [['HTTP', 'HTTPS']], 'Fedora33Server'),
        # CVE-2021-32761
        Vulnerability('RedisMisconfigurationError', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['RedisServer5.3', 'PermissionToUseCONFIGSETCommand'], ['SSH'], 'Fedora33Server'),
        # CVE-2020-35628
        Vulnerability('LIBCGALConfigurationError', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['CGAL-5.1.1'], ['SSH'], 'Fedora33Server'),
        # CVE-2021-42386
        Vulnerability('UseAfterFreeRemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['BusyBox1.33'], ['SSH'], 'Fedora33Server'),

        # CVE-2021-1695
        Vulnerability('WindowsPrintSpoolerPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['spoolsv.exe6.0'], [], 'Win2019Server'),
        # CVE-2019-0811
        Vulnerability('DNSServerVulnerability', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['DNSSECDisabled'], [['HTTP', 'HTTPS', 'SMTP'], 'RDP'], 'Win2019Server'),
        # CVE-2020-15706
        Vulnerability('SecureBootBypass', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['GRUB2Version2.04'], ['RDP'], 'Win2019Server'),
        # CVE-2019-1126
        Vulnerability('ADFSImproperSanitizationError', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['ADFSForWindows2019Server'], ['HTTP', 'RDP'], 'Win2019Server'),
        # CVE-2018-8415
        Vulnerability('PowerShellTamperingVulnerability', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['PowerShellCore6.0'], ['RDP'], 'Win2019Server'),
        # CVE-2019-1129
        Vulnerability('AppXPrivilegeEscalation', VulnerabilityType.LOCAL, VulnerabilityOutcome(),
                      ['AppXDeploymentServerEnabled'], [], 'Win2019Server'),
        # CVE-2020-0609
        Vulnerability('RDGatewayRemoteCodeExecution', VulnerabilityType.REMOTE, VulnerabilityOutcome(),
                      ['RDPVersion7.8'], ['RDP'], 'Win2019Server')]

    # From the predefined list of vulnerabilities, all the properties,protocols are gathered
    # put into respective libraries. Then a Library object is generated from these individual libraries and returned.
    os_library = ['Win7', 'Win10', 'Ubuntu16.04Server', 'Fedora33Server', 'Win2019Server']
    os_vulnerability_library = dict()
    os_vulnerability_library['Win7'] = 0.8
    os_vulnerability_library['Win10'] = 0.4
    os_vulnerability_library['Ubuntu16.04Server'] = 0.7
    os_vulnerability_library['Fedora33Server'] = 0.7
    os_vulnerability_library['Win2019Server'] = 0.4
    property_library = []
    protocol_library = []
    for vulnerability in vulnerability_library:
        for property_value in vulnerability.properties:
            if property_value not in property_library:
                property_library.append(property_value)
        for protocol_value in vulnerability.listening_protocols:
            if protocol_value not in protocol_library:
                protocol_library.append(protocol_value)
    library = Library(os_library, property_library, protocol_library, vulnerability_library, os_vulnerability_library)
    return library


# This function checks to see if the compromised attribute in the network object is set to true or false
def is_network_compromised(network):
    for node_id in network.nodesList.keys():
        if not network.nodesList[node_id].compromised:
            return False
    return True


# The generate_graph function creates a Digraph object and adds all the node information along with the edge information
# to the Digraph object.
def generate_graph(nodes_list, edges_list):
    graph = networkx.DiGraph()
    graph.add_nodes_from([(k, {'data': v}) for (k, v) in list(nodes_list.items())])
    for edge in edges_list:
        graph.add_edge(edge.firstNodeId, edge.secondNodeId)
    return graph


# The respective probabilities for attacker, defender and network are assigned in the main function.
# The generate_library() function will be called that generates and returns a Library of values. A computer network
# object is created along with a defender and attacker objects.
def main():
    number_of_nodes = int(input("Please input the desired number of nodes in the network "))
    vulnerability_chance = float(input("Please input a value between 0.0 to 1.0 to be used for assigning random node"
                                       "information "))
    attacker_chance = float(input("Please input a value between 0.0 to 1.0 to be used as ATTACKER's probability"
                                  " in compromising the network "))
    defender_chance = float(input("Please input a value between 0.0 to 1.0 to be used as DEFENDER's probability"
                                  " in protecting the network "))
    scan_capacity = int(input("Please input a integer value less than the number of nodes which determines"
                              " the number of nodes the defender can scan at a time "))

    library: Library = generate_library()
    computer_network = ComputerNetwork(number_of_nodes, library, vulnerability_chance)
    computer_network.generate_network()
    defender = Defender(scan_capacity, computer_network, defender_chance)
    attacker = Attacker(computer_network, defender, attacker_chance)
    steps = 0
    # Until a predefined number of steps is reached or the network is compromised, the attacker and defender will
    # perform their respective actions one-by-one.
    while steps != 20:
        input()
        if is_network_compromised(computer_network):
            print("\nThe attacker has taken over the network in " + str(steps) + " steps.\n")
            print("\nThe attacker's reward is " + str(attacker.reward_accumulated) + "\n")
            break
        print("step " + str(steps) + ": ")
        # If the attacker does not have enough resources to move forward in the network, the process will be stopped
        if not attacker.attack():
            print("\nThe attacker does not have enough resources to move forward in the network.\n")
            return
        defender.defend()
        steps += 1
        # Generate a Digraph object and assign the desired node layout
        # Assign edge labels and node colors to the graph object
        # Display the graph to the user
        graph = generate_graph(computer_network.nodesList, computer_network.edgesList)
        pos = networkx.circular_layout(graph, scale=20)
        label_pos = {node: node_pos + [1, -2] for node, node_pos in pos.items()}
        labels = {node_id: computer_network.nodesList[node_id].OSType for node_id in computer_network.nodesList.keys()}
        node_colors = []
        for node_id in computer_network.nodesList.keys():
            if computer_network.nodesList[node_id].compromised and \
                    computer_network.nodesList[node_id].privilegeLevel == PrivilegeLevel.SYSTEM_LEVEL:
                node_colors.append("#560000")
            elif computer_network.nodesList[node_id].compromised:
                node_colors.append("#ff0000")
            elif not computer_network.nodesList[node_id].compromised and node_id in attacker.compromised_node_ids:
                node_colors.append("#0000ff")
            elif node_id in attacker.discovered_node_ids:
                node_colors.append("#00ff00")
            else:
                node_colors.append("#999999")
        networkx.draw(graph, pos, with_labels=True, node_color=node_colors, node_size=600)
        networkx.draw_networkx_labels(graph, label_pos, labels=labels, horizontalalignment="left",
                                      verticalalignment="top")
        networkx.draw_networkx_edge_labels(graph, pos,
                                           edge_labels={(edge.firstNodeId, edge.secondNodeId): edge.vulnerability_id
                                                        for edge in computer_network.edgesList}, label_pos=0.5)
        plt.show()


main()
