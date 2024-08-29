import paramiko
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from datetime import datetime
from openpyxl import Workbook
import sys

def ssh_connect(host, user, pwd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Connecting to {host} as {user}...")
        client.connect(hostname=host, username=user, password=pwd)
        print("SSH connection established.")
        return client
    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials.")
        raise
    except paramiko.SSHException as e:
        print(f"Unable to establish SSH connection: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise

def download_file_via_ssh(ssh_client, remote_path, local_path):
    try:
        sftp = ssh_client.open_sftp()
        print(f"Downloading {remote_path} to {local_path}...")
        sftp.get(remote_path, local_path)
        sftp.close()
        print("Download successful.")
    except paramiko.SFTPError as e:
        print(f"SFTP error: {e}")
    except Exception as e:
        print(f"Unexpected error during file transfer: {e}")

def load_certificate(file_path):
    try:
        with open(file_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except Exception as e:
        print(f"Failed to load certificate: {e}")
        raise

def verify_certificate(cert, root_ca):
    try:
        root_ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        return "Certificate Authority verification passed."
    except Exception as e:
        print(f"Certificate Authority verification failed: {e}")
        return "Certificate Authority verification failed."

def check_ocsp_status(cert, issuer):
    try:
        ocsp_url = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value[0].access_location.value
        ocsp_request = x509.ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, cert.signature_hash_algorithm).build()
        response = requests.post(ocsp_url, data=ocsp_request.public_bytes(serialization.Encoding.DER), headers={'Content-Type': 'application/ocsp-request'})
        ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)
        if ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED:
            return "Certificate has been revoked."
        else:
            return "Certificate is not revoked."
    except Exception as e:
        print(f"OCSP check failed: {e}")
        return "OCSP check failed."

def check_certificate_expiry(cert):
    return "Certificate is expired." if cert.not_valid_after < datetime.now() else "Certificate is valid."

def check_device_login_security(ssh_client):
    commands = [
        "display current-configuration | include aaa",
        "display current-configuration | include authentication-mode",
        "display current-configuration | include password complexity",
        "display current-configuration | include mfa"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))
    
    strong_authentication = "Strong authentication methods are in place." if "authentication-mode" in results[1][1] else "Strong authentication methods are not in place."
    password_policies = "Password policies are enforced." if "password complexity" in results[2][1] else "Password policies are not enforced."
    mfa_enabled = "Multi-factor authentication is enabled." if "mfa" in results[3][1] else "Multi-factor authentication is not enabled."

    return [
        ["Device Login Security", strong_authentication],
        ["Device Login Security", password_policies],
        ["Device Login Security", mfa_enabled]
    ]

def check_aaa_user_management_security(ssh_client):
    commands = [
        "display aaa",
        "display user",
        "display acl all"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    auth_mechanisms = "Authentication mechanisms are securely implemented." if "aaa" in results[0][1] else "Authentication mechanisms are not securely implemented."
    user_identity_mgmt = "User identities are managed securely." if "user" in results[1][1] else "User identities are not managed securely."
    access_control_policies = "Access control policies are validated." if "acl" in results[2][1] else "Access control policies are not validated."

    return [
        ["AAA User Management Security", auth_mechanisms],
        ["AAA User Management Security", user_identity_mgmt],
        ["AAA User Management Security", access_control_policies]
    ]

def check_snmp_device_management_security(ssh_client):
    commands = [
        "display acl 2001",
        "display current-configuration | include snmp-agent",
        "display current-configuration | include mib-view",
        "display current-configuration | include snmpv3 group",
        "display current-configuration | include snmpv3 user"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    acl_config = "ACL 2001 is correctly configured." if "acl number 2001" in results[0][1] and "rule 0 deny source 10.138.20.123 0" in results[0][1] and "rule 5 permit source 10.138.90.111 0" in results[0][1] else "ACL 2001 is not correctly configured."
    snmp_acl = "SNMP ACL is configured correctly." if "snmp-agent acl 2001" in results[1][1] else "SNMP ACL is not configured correctly."
    mib_view = "MIB view iso-view is configured." if "mib-view included iso-view" in results[2][1] else "MIB view iso-view is not configured."
    snmpv3_group = "SNMPv3 group v3group is configured correctly." if "snmp-agent group v3group" in results[3][1] else "SNMPv3 group v3group is not configured correctly."
    snmpv3_user = "SNMPv3 user v3user is configured correctly." if "snmp-agent usm-user v3user" in results[4][1] else "SNMPv3 user v3user is not configured correctly."

    return [
        ["SNMP Device Management Security", acl_config],
        ["SNMP Device Management Security", snmp_acl],
        ["SNMP Device Management Security", mib_view],
        ["SNMP Device Management Security", snmpv3_group],
        ["SNMP Device Management Security", snmpv3_user]
    ]

def check_service_plane_access_prohibition(ssh_client):
    commands = [
        "display current-configuration | include cpu-defend policy"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    required_config = [
        "deny packet-type telnet",
        "deny packet-type ssh",
        "deny packet-type http",
        "deny packet-type snmp",
        "deny packet-type ftp",
        "deny packet-type icmp"
    ]

    config_check = all(config in results[0][1] for config in required_config)
    service_plane_security = "Service plane access prohibition is correctly configured." if config_check else "Service plane access prohibition is not correctly configured."

    return [["Service Plane Access Prohibition of Insecure Management Protocols", service_plane_security]]

def check_mpac(ssh_client):
    commands = [
        "display current-configuration | include service-security policy",
        "display current-configuration | include service-security global-binding",
        "display current-configuration | include ssh server enable",
        "display current-configuration | include http secure-server enable",
        "display current-configuration | include service-security policy ipv4 test",
        "display current-configuration | include rule 10 deny protocol ip source-ip 10.10.1.1 0"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    protocol_filtering = "Protocol filtering is configured correctly." if "service-security policy" in results[0][1] else "Protocol filtering is not configured correctly."
    acl_implementation = "ACLs are implemented correctly." if "service-security global-binding" in results[1][1] else "ACLs are not implemented correctly."
    ssh_configured = "SSH is configured as the primary method for command-line access." if "ssh server enable" in results[2][1] else "SSH is not configured as the primary method for command-line access."
    https_configured = "HTTPS is used for web-based management." if "http secure-server enable" in results[3][1] else "HTTPS is not used for web-based management."

    ipv4_policy = "IPv4 MPAC policy is configured correctly." if "service-security policy ipv4 test" in results[4][1] and "rule 10 deny protocol ip source-ip 10.10.1.1 0" in results[5][1] else "IPv4 MPAC policy is not configured correctly."

    return [
        ["MPAC - Protocol Filtering", protocol_filtering],
        ["MPAC - Access Control Lists", acl_implementation],
        ["MPAC - SSH for Command-Line Access", ssh_configured],
        ["MPAC - HTTPS for Web-based Management", https_configured],
        ["MPAC - IPv4 MPAC Policy", ipv4_policy]
    ]

def check_local_attack_defense(ssh_client):
    commands = [
        "display current-configuration | include cpu-attack defense",
        "display current-configuration | include attack-source tracing",
        "display current-configuration | include port-attack defense",
        "display current-configuration | include user-level rate limiting"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    cpu_defense = "CPU attack defense is configured." if "cpu-attack defense" in results[0][1] else "CPU attack defense is not configured."
    source_tracing = "Attack source tracing is enabled." if "attack-source tracing" in results[1][1] else "Attack source tracing is not enabled."
    port_defense = "Port attack defense is enabled." if "port-attack defense" in results[2][1] else "Port attack defense is not enabled."
    rate_limiting = "User-level rate limiting is enabled." if "user-level rate limiting" in results[3][1] else "User-level rate limiting is not enabled."

    return [
        ["Local Attack Defense - CPU Attack Defense", cpu_defense],
        ["Local Attack Defense - Attack Source Tracing", source_tracing],
        ["Local Attack Defense - Port Attack Defense", port_defense],
        ["Local Attack Defense - User-Level Rate Limiting", rate_limiting]
    ]

def check_attack_defense_service_management_isolation(ssh_client):
    commands = [
        "display current-configuration | include network-segment",
        "display current-configuration | include service-isolation",
        "display current-configuration | include management-vlan"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    network_segmentation = "Network segmentation is configured correctly." if "network-segment" in results[0][1] else "Network segmentation is not configured correctly."
    service_isolation = "Service isolation is configured correctly." if "service-isolation" in results[1][1] else "Service isolation is not configured correctly."
    management_isolation = "Management interface isolation is configured correctly." if "management-vlan" in results[2][1] else "Management interface isolation is not configured correctly."

    return [
        ["Attack Defense - Network Segmentation", network_segmentation],
        ["Attack Defense - Service Isolation", service_isolation],
        ["Attack Defense - Management Interface Isolation", management_isolation]
    ]

def check_attack_defense(ssh_client):
    commands = [
        "display current-configuration | include threat-intelligence",
        "display current-configuration | include vulnerability-management",
        "display current-configuration | include idps"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    threat_intelligence = "Threat intelligence integration is configured." if "threat-intelligence" in results[0][1] else "Threat intelligence integration is not configured."
    vulnerability_management = "Vulnerability management is effective." if "vulnerability-management" in results[1][1] else "Vulnerability management is not effective."
    idps_configured = "IDPS is deployed and configured." if "idps" in results[2][1] else "IDPS is not deployed and configured."

    return [
        ["Attack Defense - Threat Intelligence Integration", threat_intelligence],
        ["Attack Defense - Vulnerability Management", vulnerability_management],
        ["Attack Defense - IDPS Deployment", idps_configured]
    ]

def check_acl(ssh_client):
    commands = [
        "display acl all",
        "display acl rule"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    syntax_and_configuration = "ACL syntax and configuration are correct." if "acl number" in results[0][1] and "rule" in results[1][1] else "ACL syntax and configuration are incorrect."
    return [["ACL - Syntax and Configuration", syntax_and_configuration]]

def check_traffic_suppression_storm_control(ssh_client):
    commands = [
        "display current-configuration | include storm-control",
        "display current-configuration | include suppression"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    threshold_configuration = "Traffic suppression and storm control thresholds are configured correctly." if "storm-control" in results[0][1] else "Traffic suppression and storm control thresholds are not configured correctly."
    supported_protocols = "Traffic suppression mechanisms support relevant protocols." if "suppression" in results[1][1] else "Traffic suppression mechanisms do not support relevant protocols."

    return [
        ["Traffic Suppression and Storm Control - Threshold Configuration", threshold_configuration],
        ["Traffic Suppression and Storm Control - Supported Protocols", supported_protocols]
    ]

def check_trusted_path_based_forwarding(ssh_client):
    commands = [
        "display current-configuration | include routing",
        "display current-configuration | include control-plane",
        "display current-configuration | include physical-security"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    path_verification = "Trusted paths are established and verified." if "routing" in results[0][1] else "Trusted paths are not established and verified."
    control_plane_security = "Control plane security is implemented." if "control-plane" in results[1][1] else "Control plane security is not implemented."
    infrastructure_integrity = "Infrastructure integrity is maintained." if "physical-security" in results[2][1] else "Infrastructure integrity is not maintained."

    return [
        ["Trusted Path-based Forwarding - Path Verification", path_verification],
        ["Trusted Path-based Forwarding - Control Plane Security", control_plane_security],
        ["Trusted Path-based Forwarding - Infrastructure Integrity", infrastructure_integrity]
    ]

def check_information_center_security(ssh_client):
    commands = [
        "display current-configuration | include access-control",
        "display current-configuration | include data-encryption",
        "display current-configuration | include network-segmentation"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    access_controls = "Access controls are implemented." if "access-control" in results[0][1] else "Access controls are not implemented."
    data_encryption = "Data encryption is in place." if "data-encryption" in results[1][1] else "Data encryption is not in place."
    network_segmentation = "Network segmentation is in place." if "network-segmentation" in results[2][1] else "Network segmentation is not in place."

    return [
        ["Information Center Security - Access Controls", access_controls],
        ["Information Center Security - Data Encryption", data_encryption],
        ["Information Center Security - Network Segmentation", network_segmentation]
    ]

def check_hwtacacs_user_management_security(ssh_client):
    commands = [
        "display current-configuration | include hwtacacs-server",
        "display current-configuration | include authentication-mode",
        "display current-configuration | include authorization-mode",
        "display current-configuration | include accounting-mode"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    config_review = "HWTACACS is configured correctly." if "hwtacacs-server" in results[0][1] else "HWTACACS is not configured correctly."
    auth_mechanisms = "Strong authentication mechanisms are implemented." if "authentication-mode" in results[1][1] else "Strong authentication mechanisms are not implemented."
    authz_policies = "Authorization policies are implemented correctly." if "authorization-mode" in results[2][1] else "Authorization policies are not implemented correctly."
    accounting_config = "Accounting is configured correctly." if "accounting-mode" in results[3][1] else "Accounting is not configured correctly."

    return [
        ["HWTACACS User Management Security - Configuration Review", config_review],
        ["HWTACACS User Management Security - Authentication Mechanisms", auth_mechanisms],
        ["HWTACACS User Management Security - Authorization Policies", authz_policies],
        ["HWTACACS User Management Security - Accounting Configuration", accounting_config]
    ]

def check_arp_security(ssh_client):
    commands = [
        "display current-configuration | include arp anti-attack",
        "display current-configuration | include arp static",
        "display current-configuration | include arp dynamic-timeout"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    arp_spoofing_detection = "ARP spoofing detection is enabled." if "arp anti-attack" in results[0][1] else "ARP spoofing detection is not enabled."
    static_arp_entries = "Static ARP entries are configured." if "arp static" in results[1][1] else "Static ARP entries are not configured."
    dynamic_arp_aging = "Dynamic ARP aging is configured." if "arp dynamic-timeout" in results[2][1] else "Dynamic ARP aging is not configured."

    return [
        ["ARP Security - ARP Spoofing Detection", arp_spoofing_detection],
        ["ARP Security - Static ARP Entries", static_arp_entries],
        ["ARP Security - Dynamic ARP Aging", dynamic_arp_aging]
    ]

def check_dhcp_security(ssh_client):
    commands = [
        "display current-configuration | include dhcp authentication",
        "display current-configuration | include ip pool",
        "display current-configuration | include arp inspection"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    dhcp_auth = "DHCP authentication mechanisms are implemented." if "dhcp authentication" in results[0][1] else "DHCP authentication mechanisms are not implemented."
    ip_management = "IP address management practices are in place." if "ip pool" in results[1][1] else "IP address management practices are not in place."
    arp_inspection = "Dynamic ARP Inspection (DAI) is enabled." if "arp inspection" in results[2][1] else "Dynamic ARP Inspection (DAI) is not enabled."

    return [
        ["DHCP Security - Authentication Mechanisms", dhcp_auth],
        ["DHCP Security - IP Address Management", ip_management],
        ["DHCP Security - Dynamic ARP Inspection (DAI)", arp_inspection]
    ]

def check_mpls_security(ssh_client):
    commands = [
        "display current-configuration | include ldp authentication",
        "display current-configuration | include mpls-te",
        "display current-configuration | include mpls vpn"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    ldp_auth = "LDP authentication is configured." if "ldp authentication" in results[0][1] else "LDP authentication is not configured."
    mpls_te = "MPLS-TE security is implemented." if "mpls-te" in results[1][1] else "MPLS-TE security is not implemented."
    mpls_vpn = "MPLS VPN security is configured." if "mpls vpn" in results[2][1] else "MPLS VPN security is not configured."

    return [
        ["MPLS Security - LDP Authentication", ldp_auth],
        ["MPLS Security - MPLS-TE Security", mpls_te],
        ["MPLS Security - MPLS VPN Security", mpls_vpn]
    ]

def check_multicast_security(ssh_client):
    commands = [
        "display current-configuration | include igmp snooping",
        "display current-configuration | include igmp authentication",
        "display current-configuration | include multicast acl"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    igmp_snooping = "IGMP snooping is enabled." if "igmp snooping" in results[0][1] else "IGMP snooping is not enabled."
    igmp_auth = "IGMP authentication is configured." if "igmp authentication" in results[1][1] else "IGMP authentication is not configured."
    multicast_acl = "Multicast ACLs are implemented." if "multicast acl" in results[2][1] else "Multicast ACLs are not implemented."

    return [
        ["Multicast Security - IGMP Snooping", igmp_snooping],
        ["Multicast Security - IGMP Authentication", igmp_auth],
        ["Multicast Security - Multicast ACLs", multicast_acl]
    ]

def check_svf_system_security(ssh_client):
    commands = [
        "display current-configuration | include ntp authentication",
        "display current-configuration | include acl",
        "display current-configuration | include ntp peer"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        #output is.stdout.read().decode()
        output = stdout.read().decode()
        results.append((command, output.strip()))

    ntp_auth = "NTP authentication mechanisms are implemented." if "ntp authentication" in results[0][1] else "NTP authentication mechanisms are not implemented."
    ntp_acl = "NTP ACLs are configured correctly." if "acl" in results[1][1] else "NTP ACLs are not configured correctly."
    ntp_peer_auth = "NTP peer authentication is enabled." if "ntp peer" in results[2][1] else "NTP peer authentication is not enabled."

    return [
        ["SVF System Security - NTP Authentication Mechanisms", ntp_auth],
        ["SVF System Security - NTP ACLs", ntp_acl],
        ["SVF System Security - NTP Peer Authentication", ntp_peer_auth]
    ]

def check_ntp_security(ssh_client):
    commands = [
        "display current-configuration | include ntp authentication",
        "display current-configuration | include acl",
        "display current-configuration | include ntp peer"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    ntp_auth = "NTP authentication mechanisms are implemented." if "ntp authentication" in results[0][1] else "NTP authentication mechanisms are not implemented."
    ntp_acl = "NTP ACLs are configured correctly." if "acl" in results[1][1] else "NTP ACLs are not configured correctly."
    ntp_peer_auth = "NTP peer authentication is enabled." if "ntp peer" in results[2][1] else "NTP peer authentication is not enabled."

    return [
        ["NTP Security - NTP Authentication Mechanisms", ntp_auth],
        ["NTP Security - NTP ACLs", ntp_acl],
        ["NTP Security - NTP Peer Authentication", ntp_peer_auth]
    ]

def check_mstp_security(ssh_client):
    commands = [
        "display current-configuration | include stp root",
        "display current-configuration | include bpdu filter",
        "display current-configuration | include bpdu guard",
        "display current-configuration | include bpdu rate-limit"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    root_protection = "Root bridge protection is configured correctly." if "stp root" in results[0][1] else "Root bridge protection is not configured correctly."
    bpdu_filtering = "BPDU filtering is enabled." if "bpdu filter" in results[1][1] else "BPDU filtering is not enabled."
    bpdu_guard = "BPDU guard is enabled." if "bpdu guard" in results[2][1] else "BPDU guard is not enabled."
    bpdu_rate_limiting = "BPDU rate limiting is configured correctly." if "bpdu rate-limit" in results[3][1] else "BPDU rate limiting is not configured correctly."

    return [
        ["MSTP Security - Root Bridge Protection", root_protection],
        ["MSTP Security - BPDU Filtering", bpdu_filtering],
        ["MSTP Security - BPDU Guard", bpdu_guard],
        ["MSTP Security - BPDU Rate Limiting", bpdu_rate_limiting]
    ]

def check_vrrp_security(ssh_client):
    commands = [
        "display current-configuration | include vrrp authentication-mode",
        "display current-configuration | include vrrp preempt-mode",
        "display current-configuration | include ipsec policy"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    vrrp_auth = "VRRP authentication mechanisms are implemented." if "vrrp authentication-mode" in results[0][1] else "VRRP authentication mechanisms are not implemented."
    secure_comm = "Secure communication channels are used for VRRP." if "ipsec policy" in results[2][1] else "Secure communication channels are not used for VRRP."
    preemption_control = "VRRP preemption control is configured correctly." if "vrrp preempt-mode" in results[1][1] else "VRRP preemption control is not configured correctly."

    return [
        ["VRRP Security - Authentication Mechanisms", vrrp_auth],
        ["VRRP Security - Secure Communication Channels", secure_comm],
        ["VRRP Security - Preemption Control", preemption_control]
    ]


def check_etrunk_security(ssh_client):
    commands = [
        "display current-configuration | include etrunk authentication",
        "display current-configuration | include acl",
        "display current-configuration | include audit log"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    auth_mechanisms = "E-Trunk authentication mechanisms are implemented." if "etrunk authentication" in results[0][1] else "E-Trunk authentication mechanisms are not implemented."
    access_control = "E-Trunk access control policies are implemented." if "acl" in results[1][1] else "E-Trunk access control policies are not implemented."
    audit_logging = "E-Trunk audit logging is enabled." if "audit log" in results[2][1] else "E-Trunk audit logging is not enabled."

    return [
        ["E-Trunk Security - Authentication Mechanisms", auth_mechanisms],
        ["E-Trunk Security - Access Control", access_control],
        ["E-Trunk Security - Audit Logging", audit_logging]
    ]

def check_easydeploy_system_security(ssh_client):
    commands = [
        "display current-configuration | include icmpv6 filter",
        "display current-configuration | include ndp",
        "display current-configuration | include ra guard"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    icmpv6_filtering = "ICMPv6 filtering is implemented." if "icmpv6 filter" in results[0][1] else "ICMPv6 filtering is not implemented."
    ndp_security = "NDP security measures are implemented." if "ndp" in results[1][1] else "NDP security measures are not implemented."
    ra_guard = "RA Guard is enabled." if "ra guard" in results[2][1] else "RA Guard is not enabled."

    return [
        ["EasyDeploy System Security - ICMPv6 Filtering", icmpv6_filtering],
        ["EasyDeploy System Security - NDP Security", ndp_security],
        ["EasyDeploy System Security - RA Guard", ra_guard]
    ]

def check_icmpv6_attack_defense(ssh_client):
    commands = [
        "display current-configuration | include icmpv6 filter",
        "display current-configuration | include ndp",
        "display current-configuration | include icmpv6 rate-limit",
        "display current-configuration | include icmpv6 flood"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    icmpv6_filtering = "ICMPv6 message filtering is implemented." if "icmpv6 filter" in results[0][1] else "ICMPv6 message filtering is not implemented."
    ndp_protection = "NDP protection mechanisms are implemented." if "ndp" in results[1][1] else "NDP protection mechanisms are not implemented."
    icmpv6_rate_limiting = "ICMPv6 rate limiting is configured." if "icmpv6 rate-limit" in results[2][1] else "ICMPv6 rate limiting is not configured."
    icmpv6_flood_protection = "ICMPv6 flood protection is enabled." if "icmpv6 flood" in results[3][1] else "ICMPv6 flood protection is not enabled."

    return [
        ["Defense Against ICMPv6 Attacks - ICMPv6 Message Filtering", icmpv6_filtering],
        ["Defense Against ICMPv6 Attacks - NDP Protection", ndp_protection],
        ["Defense Against ICMPv6 Attacks - ICMPv6 Rate Limiting", icmpv6_rate_limiting],
        ["Defense Against ICMPv6 Attacks - ICMPv6 Flood Protection", icmpv6_flood_protection]
    ]


def check_defense_against_ip_packet_route_options(ssh_client):
    commands = [
        "display firewall rule all",
        "display current-configuration | include route-options",
        "display current-configuration | include ingress-filtering"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    packet_filtering = "Packet filtering and inspection mechanisms are in place." if "route-options" in results[1][1] else "Packet filtering and inspection mechanisms are not in place."
    firewall_rules = "Firewall rules to deny IP packets with Route Options are configured." if "firewall rule" in results[0][1] else "Firewall rules to deny IP packets with Route Options are not configured."
    ingress_filtering = "Ingress filtering policies to prevent spoofed IP packets are implemented." if "ingress-filtering" in results[2][1] else "Ingress filtering policies to prevent spoofed IP packets are not implemented."

    return [
        ["Defense Against IP Packets with Route Options - Packet Filtering and Inspection", packet_filtering],
        ["Defense Against IP Packets with Route Options - Firewall Rules", firewall_rules],
        ["Defense Against IP Packets with Route Options - Ingress Filtering", ingress_filtering]
    ]

def check_defense_against_ip_spoofing(ssh_client):
    commands = [
        "display current-configuration | include ingress-filtering",
        "display current-configuration | include egress-filtering",
        "display current-configuration | include rpf"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    ingress_filtering = "Ingress filtering is implemented to block spoofed IP packets." if "ingress-filtering" in results[0][1] else "Ingress filtering is not implemented to block spoofed IP packets."
    egress_filtering = "Egress filtering is implemented to block spoofed IP packets." if "egress-filtering" in results[1][1] else "Egress filtering is not implemented to block spoofed IP packets."
    rpf_checks = "RPF checks are enabled to verify the legitimacy of source IP addresses." if "rpf" in results[2][1] else "RPF checks are not enabled to verify the legitimacy of source IP addresses."

    return [
        ["Defense Against IP Address Spoofing - Ingress Filtering", ingress_filtering],
        ["Defense Against IP Address Spoofing - Egress Filtering", egress_filtering],
        ["Defense Against IP Address Spoofing - Reverse Path Forwarding (RPF)", rpf_checks]
    ]

def check_data_transmission_security(ssh_client):
    commands = [
        "display current-configuration | include tls",
        "display current-configuration | include ipsec",
        "display current-configuration | include certificate",
        "display current-configuration | include key-management"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    encryption_protocols = "Strong encryption protocols are implemented." if "tls" in results[0][1] or "ipsec" in results[1][1] else "Strong encryption protocols are not implemented."
    certificate_management = "Proper certificate management practices are in place." if "certificate" in results[2][1] else "Proper certificate management practices are not in place."
    key_management = "Secure key management practices are implemented." if "key-management" in results[3][1] else "Secure key management practices are not implemented."

    return [
        ["Data Transmission Security - Encryption Protocols", encryption_protocols],
        ["Data Transmission Security - Certificate Management", certificate_management],
        ["Data Transmission Security - Key Management", key_management]
    ]

def check_ipv6_nd_security(ssh_client):
    commands = [
        "display current-configuration | include ra guard",
        "display current-configuration | include ns rate-limit",
        "display current-configuration | include send"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    ra_guard = "RA Guard is enabled to protect against rogue router advertisements." if "ra guard" in results[0][1] else "RA Guard is not enabled to protect against rogue router advertisements."
    ns_rate_limiting = "NS rate limiting is configured to prevent ND DoS attacks." if "ns rate-limit" in results[1][1] else "NS rate limiting is not configured to prevent ND DoS attacks."
    send_deployment = "SEND is implemented to secure ND messages." if "send" in results[2][1] else "SEND is not implemented to secure ND messages."

    return [
        ["IPv6 ND Security - RA Guard", ra_guard],
        ["IPv6 ND Security - NS Rate Limiting", ns_rate_limiting],
        ["IPv6 ND Security - Secure Neighbor Discovery (SEND)", send_deployment]
    ]

def check_acl_security(ssh_client):
    commands = [
        "display acl all",
        "display current-configuration | include acl rule"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    rule_analysis = "ACL rule set aligns with security policies." if "acl rule" in results[1][1] else "ACL rule set does not align with security policies."
    specificity_and_order = "ACL rules are logically organized." if "acl rule" in results[1][1] else "ACL rules are not logically organized."
    acl_testing = "ACL functionality is validated through testing." if "acl" in results[0][1] else "ACL functionality is not validated through testing."

    return [
        ["ACL Security - Rule Analysis", rule_analysis],
        ["ACL Security - Specificity and Order", specificity_and_order],
        ["ACL Security - Testing and Verification", acl_testing]
    ]

def check_port_protection(ssh_client):
    commands = [
        "display current-configuration | include physical security",
        "display current-configuration | include port security",
        "display current-configuration | include dynamic arp inspection"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    physical_security = "Physical security measures are in place." if "physical security" in results[0][1] else "Physical security measures are not in place."
    port_security_config = "Port security configurations are implemented." if "port security" in results[1][1] else "Port security configurations are not implemented."
    dynamic_arp_inspection = "DAI is enabled to prevent ARP spoofing." if "dynamic arp inspection" in results[2][1] else "DAI is not enabled to prevent ARP spoofing."

    return [
        ["Port Protection - Physical Security", physical_security],
        ["Port Protection - Port Security Configuration", port_security_config],
        ["Port Protection - Dynamic ARP Inspection (DAI)", dynamic_arp_inspection]
    ]

def check_port_isolation(ssh_client):
    commands = [
        "display current-configuration | include port isolation",
        "display current-configuration | include vlan",
        "display current-configuration | include port isolation testing"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    port_isolation_config = "Port isolation settings are configured." if "port isolation" in results[0][1] else "Port isolation settings are not configured."
    traffic_segmentation = "Network traffic is segmented." if "vlan" in results[1][1] else "Network traffic is not segmented."
    connectivity_testing = "Port isolation is validated through testing." if "port isolation testing" in results[2][1] else "Port isolation is not validated through testing."

    return [
        ["Port Isolation - Port Isolation Configuration", port_isolation_config],
        ["Port Isolation - Traffic Segmentation", traffic_segmentation],
        ["Port Isolation - Testing Connectivity", connectivity_testing]
    ]

def check_port_security(ssh_client):
    commands = [
        "display current-configuration | include port security",
        "display current-configuration | include mac address filtering",
        "display current-configuration | include mac address limiting"
    ]
    results = []

    for command in commands:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        output = stdout.read().decode()
        results.append((command, output.strip()))

    port_security_config = "Port security features are configured." if "port security" in results[0][1] else "Port security features are not configured."
    mac_address_filtering = "MAC address filtering is configured." if "mac address filtering" in results[1][1] else "MAC address filtering is not configured."
    mac_address_limiting = "MAC address limiting is configured." if "mac address limiting" in results[2][1] else "MAC address limiting is not configured."

    return [
        ["Port Security - Port Security Configuration", port_security_config],
        ["Port Security - MAC Address Filtering", mac_address_filtering],
        ["Port Security - MAC Address Limiting", mac_address_limiting]
    ]

def perform_checks(cert_path, ca_path, output_file, ssh_client):
    cert, root_ca = load_certificate(cert_path), load_certificate(ca_path)
    results = [
        ["Digital Certificate Management", verify_certificate(cert, root_ca)],
        ["Digital Certificate Management", check_ocsp_status(cert, root_ca)],
        ["Digital Certificate Management", check_certificate_expiry(cert)]
    ]
    results.extend(check_device_login_security(ssh_client))
    results.extend(check_aaa_user_management_security(ssh_client))
    results.extend(check_snmp_device_management_security(ssh_client))
    results.extend(check_service_plane_access_prohibition(ssh_client))
    results.extend(check_mpac(ssh_client))
    results.extend(check_local_attack_defense(ssh_client))
    results.extend(check_attack_defense_service_management_isolation(ssh_client))
    results.extend(check_attack_defense(ssh_client))
    results.extend(check_acl(ssh_client))
    results.extend(check_traffic_suppression_storm_control(ssh_client))
    results.extend(check_trusted_path_based_forwarding(ssh_client))
    results.extend(check_information_center_security(ssh_client))
    results.extend(check_hwtacacs_user_management_security(ssh_client))
    results.extend(check_arp_security(ssh_client))
    results.extend(check_dhcp_security(ssh_client))
    results.extend(check_mpls_security(ssh_client))
    results.extend(check_multicast_security(ssh_client))
    results.extend(check_svf_system_security(ssh_client))
    results.extend(check_ntp_security(ssh_client))
    results.extend(check_mstp_security(ssh_client))
    results.extend(check_vrrp_security(ssh_client))
    results.extend(check_etrunk_security(ssh_client))
    results.extend(check_easydeploy_system_security(ssh_client))
    results.extend(check_icmpv6_attack_defense(ssh_client))
    results.extend(check_defense_against_ip_packet_route_options(ssh_client))
    results.extend(check_defense_against_ip_spoofing(ssh_client))
    results.extend(check_data_transmission_security(ssh_client))
    results.extend(check_ipv6_nd_security(ssh_client))
    results.extend(check_acl_security(ssh_client))
    results.extend(check_port_protection(ssh_client))
    results.extend(check_port_isolation(ssh_client))
    results.extend(check_port_security(ssh_client))

    for result in results:
        print(f"Objective: {result[0]}, Result: {result[1]}")

    wb, ws = Workbook(), Workbook().active
    for row in results: ws.append(row)
    wb.save(output_file)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 huawei_routers.py <router_ip> <username> <password>")
        sys.exit(1)

    router_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]

    cert_file_path = "/flash/certificate.pem"
    ca_file_path = "/flash/rootCA.pem"
    output_excel_file = "certificate_check_results.xlsx"

    try:
        ssh_client = ssh_connect(router_ip, username, password)
        download_file_via_ssh(ssh_client, cert_file_path, "certificate.pem")
        download_file_via_ssh(ssh_client, ca_file_path, "rootCA.pem")
        ssh_client.close()

        cert = load_certificate("certificate.pem")
        root_ca = load_certificate("rootCA.pem")

        ca_verification_result = verify_certificate(cert, root_ca)
        print(ca_verification_result)

        ocsp_status = check_ocsp_status(cert, root_ca)
        print(ocsp_status)

    except Exception as e:
        print(f"An error occurred: {e}")
