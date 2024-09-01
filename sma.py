from netmiko import ConnectHandler #type:ignore
import logging
import re
import csv
# Enable logging for debugging
logging.basicConfig(filename='netmiko_debug.log', level=logging.DEBUG)
interface_name = 'loopback 1'

def connect_to_router():
    device = {
        'device_type': 'cisco_ios',
        'host': '192.168.1.1',
        'username': 'super',
        'password': 'password',
        'secret': 'password',  # Replace with your enable password
        'timeout': 60,  # Increase the timeout if needed
    }
    return ConnectHandler(**device)

def enable_mode(connection):
    try:
        connection.enable()
    except ValueError as e:
        print(f"Failed to enter enable mode: {e}")
        raise

def verify_privilege_level_1(connection):
    excluded_users = {'kshitij', 'admin', 'super', 'super2'}
    
    command = 'show run | include privilege'
    output = connection.send_command(command)
    lines = output.splitlines()
    
    # Filter lines to find all 'username' entries with 'privilege'
    privilege_lines = [line.strip() for line in lines if 'username' in line and 'privilege' in line]

    # If there are no privilege lines, return True
    if not privilege_lines:
        return True

    # Check if any 'privilege' line is not set to 1 for non-excluded users
    for line in privilege_lines:
        username = line.split()[1]
        privilege = line.split('privilege')[1].strip().split()[0]
        if username not in excluded_users and privilege != '1':
            return False

    # Return True if all non-excluded 'privilege' lines are set to 1
    return True

def verify_ssh_transport_2(connection):
    command = 'show run | sec vty'
    output = connection.send_command(command)
    lines = output.splitlines()

    transport_input_lines = [line.strip() for line in lines if line.strip().startswith('transport input')]
    
    if not transport_input_lines:
        return False  # No transport input lines found
    
    return len(transport_input_lines) == 1 and transport_input_lines[0] == 'transport input ssh'

def verify_aux_exec_disabled_3(connection):
    # Check the running configuration for the AUX port
    command_run = 'show run | sec aux'
    output_run = connection.send_command(command_run)
    
    # Verify 'no exec' is present in the configuration output
    if 'no exec' not in output_run:
        return False

    # Check the AUX line status
    command_line = 'show line aux 0 | incl EXEC'
    output_line = connection.send_command(command_line)
    
    # Verify 'no exec' is present in the line status output
    if 'Capabilities: EXEC Suppressed' not in output_line:
        return False

    # Return True if both checks are passed
    return True

def verify_acl_entries_4(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)

vty_acl_number = '10'  # Replace with the actual ACL number
required_entries = ['10', '20', '30']  # List the sequence numbers you want to verify

def verify_acl_set_5(connection, line_start, line_end, vty_acl_number):
    command = f'show run | sec vty {line_start} {line_end}'
    output_line = connection.send_command(command)
    # Check if 'access-class' is present in the output

    if 'access-class' not in output_line:
        return False

    # Return True if both checks are passed
    return True

line_start = '0'  # Replace with the starting line number
line_end = '4'    # Replace with the ending line number

def verify_timeout_configured_6(connection):
    command = 'show run | sec line aux 0'
    output = connection.send_command(command)
    
    # Look for the 'exec-timeout' line in the output
    for line in output.splitlines():
        if line.strip().startswith('exec-timeout'):
            timeout_values = line.split()[1:]  # Get the timeout values (minutes and seconds)
            if len(timeout_values) == 2:
                minutes, seconds = map(int, timeout_values)
                if minutes <= 10:
                    return True
    
    # Return False if 'exec-timeout' is not found or not within the desired range
    return False

def verify_console_timeout_configured_7(connection):
    command = 'show run | sec line con 0'
    output = connection.send_command(command)
    
    # Look for the 'exec-timeout' line in the output
    for line in output.splitlines():
        if line.strip().startswith('exec-timeout'):
            timeout_values = line.split()[1:]  # Get the timeout values (minutes and seconds)
            if len(timeout_values) == 2:
                minutes, seconds = map(int, timeout_values)
                if minutes == 9 and seconds == 59:
                    return True
    
    # Return False if 'exec-timeout' is not exactly 9 minutes 59 seconds
    return False

def verify_tty_timeout_configured_8(connection, tty_line_number):
    command = f'show line tty {tty_line_number} | begin Timeout'
    output = connection.send_command(command)
    
    # Check if 'exec-timeout' is present in the output
    return 'exec-timeout' in output
tty_line_number = '44' 

def verify_vty_timeout_configured_9(connection, vty_line_number):
    command = f'show line vty {vty_line_number} | begin Timeout'
    output = connection.send_command(command)
    return 'Idle EXEC' in output

vty_line_number = '0'  # Replace with the actual VTY line number

def verify_aux_input_transports_disabled_10(connection):
    command = 'show line aux 0 | include input transports'
    output = connection.send_command(command)
        
    # Check if the line contains "Allowed input transports are none"
    expected_transport = 'Allowed input transports are none'
    if expected_transport in output:
        return True
    else:
        return False

def verify_aaa_services_enabled_11(connection):
    command = 'show running-config | include aaa new-model'
    output = connection.send_command(command)
    return 'aaa new-model' in output

def verify_aaa_authentication_login_enabled_12(connection):
    command = 'show run | include aaa authentication login'
    output = connection.send_command(command)

    lines = output.splitlines()
    for line in lines:
        if 'aaa authentication login' in line:
            return True
    
    return False

def verify_aaa_authentication_enable_mode_13(connection):
    command = 'show running-config | include aaa authentication enable'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa authentication enable"
    if 'aaa authentication enable' in output:
        return True
    return False


def verify_aaa_accounting_commands_17(connection):
    command = 'show running-config | include aaa accounting commands'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting commands"
    if 'aaa accounting commands' in output:
        return True
    return False

def verify_aaa_accounting_connection_18(connection):
    command = 'show running-config | include aaa accounting connection'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting connection"
    if 'aaa accounting connection' in output:
        return True
    return False

def verify_aaa_accounting_exec_19(connection):
    command = 'show running-config | include aaa accounting exec'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting connection"
    if 'aaa accounting exec' in output:
        return True
    return False

def verify_aaa_accounting_network_20(connection):
    command = 'show running-config | include aaa accounting network'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting network"
    if 'aaa accounting network' in output:
        return True
    return False

def verify_aaa_accounting_system_21(connection):
    command = 'show running-config | include aaa accounting system'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting network"
    if 'aaa accounting system' in output:
        return True
    return False

def verify_exec_banne_22(connection):
    command = 'show running-config | begin banner exec'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner exec' in output:
        return True
    return False

def verify_login_banner_23(connection):
    command = 'show running-config | begin banner login'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner login' in output:
        return True
    return False

def verify_motd_banner_24(connection):
    command = 'show running-config | begin banner motd'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner motd' in output:
        return True
    return False

def verify_enable_secret_25(connection):
    command = 'show running-config | include enable secret'
    output = connection.send_command(command)
    
    # Check if the output contains 'enable secret'
    if 'enable secret' in output:
        return True
    return False

def verify_password_encryption_26(connection):
    command = 'show running-config | include service password-encryption'
    output = connection.send_command(command)
    
    
    # Check if the output contains 'service password-encryption'
    if 'no service password-encryption' in output:
        return False
    
    if 'service password-encryption' in output:
        return True

def verify_encrypted_password_user_27(connection):
    command = 'show running-config | include username'
    output = connection.send_command(command)
        
    # Check if any line contains 'secret', indicating an encrypted password
    if any('secret' in line for line in output.splitlines()):
        return True
    return False

def verify_snmp_agent_status_28(connection):
    command = 'show snmp community'
    output = connection.send_command(command)
    
    # Check if the output contains the phrase "SNMP agent not enabled"
    if "SNMP agent not enabled" in output:
        return True
    return False

def verify_public_community_string_29(connection):
    command = 'show snmp community'
    output = connection.send_command(command)

    # Check if 'private' is not present in the output
    if "private" not in output:
        return True
    return False

def verify_public_community_string_30(connection):
    command = 'show snmp community'
    output = connection.send_command(command)
    
    # Check if 'public' is not present in the output
    if "public" not in output:
        return True
    return False

def verify_rw_community_string_31(connection):
    command = 'show run | incl snmp-server community'
    output = connection.send_command(command)
    
    # Check if ' RW ' is not present in the output
    if ' RW ' not in output:
        return True
    return False

def verify_acl_enabled_32(connection):

    command = 'show run | incl snmp-server community'
    output = connection.send_command(command)
    
    # Check if the output contains a number after the community string
    if any(char.isdigit() for char in output):
        return True
    return False

def verify_acl_entries_snmp_33(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)


def verify_snmp_traps_enabled_34(connection):
    command = 'show run | incl snmp-server'
    output = connection.send_command(command)
    
    # Check if any SNMP configuration is present in the output
    if 'snmp-server enable traps' in output:
        return True
    return False

def verify_snmp_traps_enabled_35(connection):
    command = 'show run | incl snmp-server'
    output = connection.send_command(command)
    
    # Check if any SNMP configuration is present in the output
    if 'snmp-server enable traps' in output:
        return True
    return False

def verify_snmp_group_and_security_model_36(connection, expected_group_name, expected_security_model):
    command = 'show snmp group'
    output = connection.send_command(command)
        
    # Use regex to find the group name and security model in the output
    group_name_pattern = rf'groupname:\s*{expected_group_name}'
    security_model_pattern = rf'security model:\s*{expected_security_model}'
    
    group_name_match = re.search(group_name_pattern, output, re.IGNORECASE)
    security_model_match = re.search(security_model_pattern, output, re.IGNORECASE)
    
    # Check if both patterns are found in the output
    if group_name_match and security_model_match:
        return True
    return False

# Example usage
expected_group_name = 'hello'  # Replace with the expected group name
expected_security_model = 'v3 priv'  # Replace with the expected security model

def verify_snmp_user_and_security_settings_37(connection, expected_user_name, expected_security_settings):
    command = 'show snmp user'
    output = connection.send_command(command)
    
    # Use regex to find the user name and security settings in the output
    user_name_pattern = rf'username:\s*{expected_user_name}'
    security_settings_pattern = rf'security model:\s*{expected_security_settings}'
    
    user_name_match = re.search(user_name_pattern, output, re.IGNORECASE)
    security_settings_match = re.search(security_settings_pattern, output, re.IGNORECASE)
    
    # Check if both patterns are found in the output
    if user_name_match and security_settings_match:
        return True
    return False
# Example usage
expected_user_name = 'your_user_name'  # Replace with the expected user name
expected_security_settings = 'v3 priv'  # Replace with the expected security settings

def verify_hostname_38(connection):
    command = 'show run | include hostname'
    output = connection.send_command(command)
    
    # Check if 'hostname' is in the output
    if 'hostname' in output:
        return True
    return False

def verify_domain_name_39(connection):
    command = 'show run | include ip domain-name'
    output = connection.send_command(command)
    
    # Check if 'ip domain-name' is in the output
    if 'ip domain-name' in output:
        return True
    return False

def verify_rsa_key_pair_40(connection):
    command = 'show crypto key mypubkey rsa'
    output = connection.send_command(command)
        
    # Check if 'RSA key pair' is in the output
    if 'Usage: General Purpose Key' in output:
        return True
    return False

def verify_ssh_timeout_41(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if '60 secs' in output:
        return True
    return False

def verify_ssh_retry_42(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if 'retries: 3' in output:
        return True
    return False

def verify_ssh_version_43(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if 'version 2.0' in output:
        return True
    return False

def verify_cdp_disabled_44(connection):
    command = 'show cdp'
    output = connection.send_command(command)
    
    # Check if 'CDP is not enabled' is in the output
    if 'CDP is not enabled' in output:
        return True
    return False

def verify_bootp_enabled_45(connection):
    command = 'show run | include bootp'
    output = connection.send_command(command)

    # Check if 'no ip bootp server' is not present in the output
    if 'no ip bootp server' not in output:
        return True
    return False

def verify_dhcp_service_enabled_46(connection):
    command = 'show run | include dhcp'
    output = connection.send_command(command)
        
    # Check if 'no service dhcp' is not present in the output
    if 'no service dhcp' not in output:
        return True
    return False

def verify_identd_enabled_47(connection):
    command = 'show run | include identd'
    output = connection.send_command(command)
    
    # Check if there is no result for 'identd'
    if 'identd' not in output:
        return True
    return False

def verify_tcp_keepalives_in_enabled_48(connection):
    command = 'show run | include service tcp'
    output = connection.send_command(command)
    
    # Check if 'service tcp-keepalives-in' is present in the output
    if 'service tcp-keepalives-in' in output:
        return True
    return False

def verify_tcp_keepalives_out_enabled_49(connection):
    command = 'show run | include service tcp'
    output = connection.send_command(command)
    
    # Check if 'service tcp-keepalives-in' is present in the output
    if 'service tcp-keepalives-out' in output:
        return True
    return False

def verify_service_pad_disabled_50(connection):
    command = 'show run | include service pad'
    output = connection.send_command(command)
    
    # Check if 'service pad' is absent in the output
    if 'no service pad' in output:
        return True
    return False

def verify_logging_on_disabled_51(connection):
    command = 'show run | include logging on'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'loggin on' not in output:  # No result returned
        return True
    return False

def verify_logging_buffered_enabled_52(connection):
    command = 'show run | include logging buffered'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'logging buffered' in output:  # No result returned
        return True
    return False

def verify_logging_console_enabled_53(connection):
    command = 'show run | include logging console'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'logging console' in output:  # No result returned
        return True
    return False

def verify_syslog_server_enabled_54(connection):
    command = 'show run | include logging host'
    output = connection.send_command(command)
    
    # Check if there are one or more IP addresses in the output
    if 'logging host' in output:
        return True
    return 

def verify_syslog_trap_server_enabled_55(connection):
    command = 'sh log | incl Trap logging'
    output = connection.send_command(command)

    # Check if "level informational" is present in the output
    if "level informational" in output:
        return True
    return False

def verify_service_timestamps_debug_datetime_enabled_56(connection):
    command = 'sh run | incl service timestamps'
    output = connection.send_command(command)

    # Check if the output contains "service timestamps debug datetime"
    if "show-timezone" and "msec" in output:
        return True
    return False

def loggin_source_interface_57(connection):
    command = 'show run | include logging source'
    output = connection.send_command(command)
    
    # Check if 'ntp authentication-key' is present in the output
    if 'logging source-interface' in output:
        return True
    return False

def verify_ntp_authenticate_58(connection):
    command = 'show run | include ntp'
    output = connection.send_command(command)
    
    # Check if 'ntp authentication-key' is present in the output
    if 'ntp' in output:
        return True
    return False

def verify_ntp_authentication_key_59(connection):
    command = 'show run | include ntp authentication-key'
    output = connection.send_command(command)
    
    # Check if 'ntp authentication-key' is present in the output
    if 'ntp authentication-key' in output:
        return True
    return False

def verify_ntp_trusted_keys_60(connection, expected_keys_count):
    command = 'show run | include ntp trusted-key'
    output = connection.send_command(command)
    
    # Count the number of trusted NTP keys in the output
    trusted_keys = [line for line in output.splitlines() if 'ntp trusted-key' in line]
    trusted_keys_count_actual = len(trusted_keys)

    # Compare the actual count with the expected count
    if trusted_keys_count_actual == expected_keys_count:
        return True
    return False

def verify_ntp_servers_configured_61(connection):
    command = 'show run | include ntp server'
    output = connection.send_command(command)
    
    # Check if there are any NTP servers in the output
    if 'ntp server' in output:
        return True
    return False

def verify_ntp_associations_62(connection):
    command = 'show ntp associations'
    output = connection.send_command(command)
    
    # Check if there are any NTP associations in the output
    if 'address' in output:
        return True  # No NTP associations are configured
    return False

def verify_loopback_interface_defined_63(connection):
    command = 'show ip interface brief | include Loopback'
    output = connection.send_command(command)
    
    # Check if the output contains an IP address for a loopback interface
    if 'Loopback' in output and any(ip in output for ip in ['.', ':']):
        return True  # Loopback interface is defined with an IP address
    return False

def verify_aaa_services_bound_to_source_interface_64(connection):
    command = 'show run | include tacacs source | include radius source'
    output = connection.send_command(command)
    
    # Check if 'tacacs source' or 'radius source' is present in the output
    if 'tacacs source' in output or 'radius source' in output:
        return True  # AAA services are bound to a source interface
    return False

def verify_ntp_services_bound_to_source_interface_65(connection):
    command = 'show run | include ntp source'
    output = connection.send_command(command)
    
    # Check if 'ntp source' is present in the output
    if 'ntp source' in output:
        return True  # NTP services are bound to a source interface
    return False

def verify_tftp_services_bound_to_source_interface_66(connection):
    command = 'show run | include tftp source-interface'
    output = connection.send_command(command)
    
    # Check if 'tftp source-interface' is present in the output
    if 'tftp source-interface' in output:
        return True  # TFTP services are bound to a source interface
    return False

def verify_ip_source_route_enabled_67(connection):
    command = 'show run | include ip source-route'
    output = connection.send_command(command)
    
    # Check if 'ip source-route' is present in the output
    if 'no ip source-route' in output:
        return True  # `ip source-route` is enabled
    return False

def verify_proxy_arp_status_68(connection, interface):
    command = f'show ip interface {interface} | include Proxy ARP'
    output = connection.send_command(command)
    
    # Check if 'proxy-arp' is present in the output
    if 'Proxy ARP is disabled' in output:
        return True  # Proxy ARP is enabled or configured
    return False
    
def verify_no_tunnel_interfaces_defined_69(connection):
    command = 'show ip interface brief | include tunnel'
    output = connection.send_command(command)
    
    # Check if there are any tunnel interfaces in the output
    if not output.strip():
        return True  # No tunnel interfaces are defined
    return False

def verify_urpf_running_70(connection, interface):
    command = f'show ip interface {interface} | include verify source'
    output = connection.send_command(command)
    
    # Check if 'verify source' is in the output
    if 'verify source' in output:
        return True  # uRPF is running on the interface
    return False

def verify_access_list_defined_71(connection, access_list_identifier):
    command = f'show ip access-list {access_list_identifier}'
    output = connection.send_command(command)
    
    list = """10 deny ip 10.0.0.0 0.255.255.255 any log
    20 deny ip 172.16.0.0 0.15.255.255 any log
    30 deny ip 192.168.0.0 0.0.255.255 any log
    40 deny ip 127.0.0.0 0.255.255.255 any log
    50 deny ip 0.0.0.0 0.255.255.255 any log
    60 deny ip 192.0.2.0 0.0.0.255 any log
    70 deny ip 169.254.0.0 0.0.255.255 any log
    80 deny ip 224.0.0.0 31.255.255.255 any log
    90 deny ip host 255.255.255.255 any log
    100 permit ip any any log"""
    # Check if any access-list definitions are present in the output
    if list in output:
        return True  # Access-list definitions are present
    return False

def verify_access_group_applied_72(connection, interface_name):
    command = f'show run | section interface {interface_name}'
    output = connection.send_command(command)

    # Check if 'access-group' is present in the output
    if 'access-group' in output:
        return True  # Access-group is applied to the interface
    return False

def verify_key_chain_number_defined_74(connection):
    command = 'show run | section key chain'
    output = connection.send_command(command)
    
    # Check if 'key chain' is present in the output
    if 'key 1' in output:
        return True  # Key chain is defined
    return False

def verify_key_chain_string_defined_75(connection):
    command = 'show run | section key chain'
    output = connection.send_command(command)
    
    # Check if 'key chain' is present in the output
    if 'key-string 7' in output:
        return True  # Key chain is defined
    return False

def ip_authentication_key_chain_eigrp_80(connection, interface_name):
    command = f'show run interface {interface_name} | include key-chain'
    output = connection.send_command(command)
    
    # Check if 'key-chain' is present in the output
    if 'key-chain' in output:
        return True  # Key chain is set on the interface
    return False

def verify_authentication_mode_on_interface_81(connection, interface_name):
    command = f'show run interface {interface_name} | include authentication mode'
    output = connection.send_command(command)
    
    # Print the command output for debugging
    print("Command Output:\n", output)
    
    # Check if 'authentication mode' is present in the output
    if 'authentication mode md5' in output:
        return True  # Authentication mode is set on the interface
    return False

def verify_message_digest_for_ospf_82(connection):
    command = 'show run | section router ospf'
    output = connection.send_command(command)
    
    # Print the command output for debugging
    print("Command Output:\n", output)
    
    # Check if 'message-digest' is present in the output
    if 'message-digest' in output:
        return True  # Message digest for OSPF is defined
    return False

def verify_md5_key_on_interface_83(connection, interface_name):
    command = f'show run int {interface_name}'
    output = connection.send_command(command)
    
    # Check if 'md5' is present in the output for the given interface
    if 'md5' in output:
        return True  # MD5 key is defined on the interface
    return False

def verify_key_chain_defined_84(connection):
    command = 'show run | section key chain'
    output = connection.send_command(command)
    
    # Check if 'key chain' is present in the output
    if 'key chain' in output:
        return True  # Key chain is defined
    return False

def verify_key_chain_defined_85(connection):
    command = 'show run | section key chain'
    output = connection.send_command(command)
    
    # Check if 'key chain' is present in the output
    if 'key 1' in output:
        return True  # Key chain is defined
    return False

def verify_key_chain_defined_86(connection):
    command = f'show run interface {interface_name} | include key-chain'
    output = connection.send_command(command)

    # Check if 'key-chain' is present in the output
    if 'key-chain' in output:
        return True  # Key chain mode is set on the interface
    return False

def verify_key_chain_defined_87(connection):
    command = 'show run | section key chain'
    output = connection.send_command(command)    
    # Check if 'key chain' is present in the output
    if 'key-string 7' in output:
        return True  # Key chain is defined
    return False

def rip_rip_authentication_mode_md5_88(connection):
    command = f'show run interface {interface_name} | include md5'
    output = connection.send_command(command)
    
    # Check if 'md5' is present in the output
    if 'md5' in output:
        return True  # MD5 mode is set on the interface
    return False

def verify_bgp_neighbor_password_89(connection):
    command = 'show run | section router bgp'
    output = connection.send_command(command)
    
    # Check if 'password' is present in the BGP configuration
    if 'password' in output:
        return True  # Neighbor password is defined in the BGP configuration
    return False

def main():
    connection = connect_to_router()
    enable_mode(connection)  # Enter enable mode
    
    results = []

    # Existing checks
    result = verify_privilege_level_1(connection)
    results.append({
        'Serial Number': 1,
        'Objective': 'Verify that non-excluded users are set to privilege level 1.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    result = verify_ssh_transport_2(connection)
    results.append({
        'Serial Number': 2,
        'Objective': 'Verify that SSH is the only transport method for VTY logins.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    result = verify_aux_exec_disabled_3(connection)
    results.append({
        'Serial Number': 3,
        'Objective': 'Verify that the EXEC process for the AUX port is disabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    vty_acl_number = 100
    required_entries = ['entry1', 'entry2']
    result = verify_acl_entries_4(connection, vty_acl_number, required_entries)
    results.append({
        'Serial Number': 4,
        'Objective': f'Check if ACL {vty_acl_number} contains required entries: {", ".join(required_entries)}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    line_start = 0
    line_end = 4
    result = verify_acl_set_5(connection, line_start, line_end, vty_acl_number)
    results.append({
        'Serial Number': 5,
        'Objective': f'Check if access-class is set for VTY lines {line_start} to {line_end}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    result = verify_timeout_configured_6(connection)
    results.append({
        'Serial Number': 6,
        'Objective': 'Verify that a timeout of 10 minutes or less is configured for the AUX line.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    result = verify_console_timeout_configured_7(connection)
    results.append({
        'Serial Number': 7,
        'Objective': 'Verify that a timeout of exactly 9 minutes 59 seconds or less is configured for the console line.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    # New check: TTY Line Timeout
    tty_line_number = 1  # Set appropriate TTY line number
    result = verify_tty_timeout_configured_8(connection, tty_line_number)
    results.append({
        'Serial Number': 8,
        'Objective': f'Verify that a timeout is configured for TTY line {tty_line_number}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': result
    })

    # Write results to CSV
    with open('compliance_report.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Objective', 'Result', 'Compliance'])
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    main()
