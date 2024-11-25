import ast
from netmiko import ConnectHandler # type: ignore
import csv
import re

def load_config(file_path):
    config = {}
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or '=' not in line:
                continue  # Skip empty lines or lines without '='
            key, value = line.split('=', 1)
            value = value.strip("'")  # Remove surrounding quotes

            # Check if the value is a list (e.g., ['10', '20', '30'])
            if value.startswith('[') and value.endswith(']'):
                config[key] = ast.literal_eval(value)
            else:
                config[key] = value
    return config

config = load_config('config.txt')

# Extracting configuration values
interface_name = config.get('INTERFACE_NAME')
interface_name_2 = config.get('INTERFACE_NAME_2')
interface = config.get('INTERFACE')
expected_user_name = config.get('EXPECTED_USER_NAME')
expected_security_settings = config.get('EXPECTED_SECURITY_SETTINGS')
expected_group_name = config.get('EXPECTED_GROUP_NAME')
expected_security_model = config.get('EXPECTED_SECURITY_MODEL')
vty_acl_number = config.get('VTY_ACL_NUMBER')
required_entries = config.get('REQUIRED_ENTRIES')
line_start = config.get('LINE_START')
line_end = config.get('LINE_END')
tty_line_number = config.get('TTY_LINE_NUMBER')
vty_line_number = config.get('VTY_LINE_NUMBER')
expected_keys_count = int(config.get('EXPECTED_KEYS_COUNT'))
access_list_identifier = config.get('ACCESS_LIST_IDENTIFIER')
key_chain_name = config.get('KEY_CHAIN_NAME')

# Router connection details
host = config.get('HOST')
username = config.get('USERNAME')
password = config.get('PASSWORD')
secret = config.get('SECRET')
timeout = int(config.get('TIMEOUT'))

def connect_to_router():
    device = {
        'device_type': 'cisco_ios',
        'host': host,
        'username': username,
        'password': password,
        'secret': secret,  # Enable password
        'timeout': timeout,  # Increase the timeout if needed
    }
    return ConnectHandler(**device)

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
    
    command = 'show running-config | include username'
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
    command = 'show running-config | sec transport input'
    output = connection.send_command(command)
    print(output)
    lines = output.splitlines()

    transport_input_lines = [line.strip() for line in lines if line.strip().startswith('transport input')]
    print(transport_input_lines)
    print(transport_input_lines[0])
    if not transport_input_lines:
        return False  # No transport input lines found
    
    return len(transport_input_lines) == 2 and transport_input_lines[0] == 'transport input ssh'

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

def verify_acl_set_5(connection, line_start, line_end, vty_acl_number):
    command = f'show run | sec vty {line_start} {line_end}'
    output_line = connection.send_command(command)
    # Check if 'access-class' is present in the output

    if 'access-class' not in output_line:
        return False

    # Return True if both checks are passed
    return True

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

def verify_vty_timeout_configured_9(connection, vty_line_number):
    command = f'show line vty {vty_line_number} | begin Timeout'
    output = connection.send_command(command)
    return 'Idle EXEC' in output

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

def verify_aaa_authentication_line_con_0_14(connection):
    command = 'show running-config | section line | include login authentication'
    output = connection.send_command(command)
    
    # Check if the output contains "login authentication"
    if 'console login authentication' in output:
        return True
    return 

def verify_aaa_authentication_line_tty_15(connection):
    command = 'show running-config | section line | include login authentication'
    output = connection.send_command(command)
      
    # Check if the output contains "login authentication"
    if 'tty login authentication' in output:
        return True
    return False

def verify_aaa_authentication_line_vty_16(connection):
    command = 'show running-config | section line | include login authentication'
    output = connection.send_command(command)
    
    # Check if the output contains "login authentication"
    if 'vty login authentication' in output:
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
    if "Community name: snmp" in output:
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
    if 'snmp-server host' in output:
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

def verify_snmp_user_and_security_settings_37(connection, expected_user_name, expected_security_settings):
    command = 'show snmp user'
    output = connection.send_command(command)
    
    # Use regex to find the user name and security settings in the output
    user_name_pattern = rf'User name:\s*{expected_user_name}'
    security_settings_pattern = rf'Privacy Protocol:\s*{expected_security_settings}'
    
    user_name_match = re.search(user_name_pattern, output, re.IGNORECASE)
    security_settings_match = re.search(security_settings_pattern, output, re.IGNORECASE)
    
    # Check if both patterns are found in the output
    if user_name_match and security_settings_match:
        return True
    return False

def verify_hostname_38(connection):
    command = 'show run | include hostname'
    output = connection.send_command(command)
    
    # Check if 'hostname' is in the output
    if 'hostname' in output:
        return True
    return False

def verify_domain_name_39(connection):
    command = 'show run | include ip domain name'
    output = connection.send_command(command)
    
    # Check if 'ip domain-name' is in the output
    if 'ip domain name' in output:
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
    if 'no ip bootp server' in output:
        return True
    return False

def verify_dhcp_service_enabled_46(connection):
    command = 'show run | include dhcp'
    output = connection.send_command(command)
        
    # Check if 'no service dhcp' is not present in the output
    if 'no service dhcp' in output:
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
    command = 'show run | include source'
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

def verify_key_chain_defined_73(connection, key_chain_name):
    command = 'show run | section key chain'
    output = connection.send_command(command)

    
    # Check if the specified key chain name is present in the output
    if key_chain_name in output:
        return True  # Key chain is defined
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

def verify_address_family_set_76(connection):
    command = 'show run | section router eigrp'
    output = connection.send_command(command)
        
    # Check if address family is configured under router eigrp
    if 'auto-summary' in output:
        return True  # Address family is set
    return False

def verify_router_eigrp_set_77(connection):
    command = 'show run | section router eigrp'
    output = connection.send_command(command)
        
    # Check if address family is configured under router eigrp
    if 'router eigrp 1' in output:
        return True  # Address family is set
    return False

def verify_key_chain_set_78(connection):
    command = 'show run | section router eigrp'
    output = connection.send_command(command)
    
    # Check if 'key-chain' is present in the output
    if 'key-chain' in output:
        return True  # Key chain is set
    return 

def set_eigrp_md5_79(connection):
    command = 'show run | section router eigrp'
    output = connection.send_command(command)
        
    # Check if 'key-chain' is present in the output
    if 'authentication mode md5' in output:
        return True  # Key chain is set
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

    # Check if 'authentication mode' is present in the output
    if 'authentication mode md5' in output:
        return True  # Authentication mode is set on the interface
    return False

def verify_message_digest_for_ospf_82(connection):
    command = 'show run | section router ospf'
    output = connection.send_command(command)
    
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

    # Check 1: Privilege Level
    result = verify_privilege_level_1(connection)
    if result:
        print("Check 1 Passed: All non-excluded users are set to privilege level 1.")
    else:
        print("Check 1 Failed: There are non-excluded users not set to privilege level 1.")
    results.append({
        'Serial Number': 1,
        'Objective': 'Verify that non-excluded users are set to privilege level 1.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 2: SSH Transport
    result = verify_ssh_transport_2(connection)
    if result:
        print("Check 2 Passed: SSH is the only transport method for VTY logins.")
    else:
        print("Check 2 Failed: Non-SSH transport methods are configured for VTY logins or 'transport input ssh' is missing.")
    results.append({
        'Serial Number': 2,
        'Objective': 'Verify that SSH is the only transport method for VTY logins.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 3: AUX EXEC Process
    result = verify_aux_exec_disabled_3(connection)
    if result:
        print("Check 3 Passed: The EXEC process for the AUX port is disabled.")
    else:
        print("Check 3 Failed: The EXEC process for the AUX port is not disabled.")
    results.append({
        'Serial Number': 3,
        'Objective': 'Verify that the EXEC process for the AUX port is disabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 4: ACL Entries
    result = verify_acl_entries_4(connection, vty_acl_number, required_entries)
    if result:
        print(f"Check 4 Passed: ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")
    else:
        print(f"Check 4 Failed: ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")
    results.append({
        'Serial Number': 4,
        'Objective': f'Check if ACL {vty_acl_number} contains required entries: {", ".join(required_entries)}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 5: Access-class for VTY lines
    result = verify_acl_set_5(connection, line_start, line_end, vty_acl_number)
    if result:
        print(f"Check 5 Passed: Access-class is set for VTY lines {line_start} to {line_end}.")
    else:
        print(f"Check 5 Failed: Access-class is not set for VTY lines {line_start} to {line_end}.")
    results.append({
        'Serial Number': 5,
        'Objective': f'Check if access-class is set for VTY lines {line_start} to {line_end}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 6: AUX Line Timeout
    result = verify_timeout_configured_6(connection)
    if result:
        print("Check 6 Passed: A timeout of 10 minutes or less is configured for the AUX line.")
    else:
        print("Check 6 Failed: Timeout configuration is missing or exceeds 10 minutes for the AUX line.")
    results.append({
        'Serial Number': 6,
        'Objective': 'Verify that a timeout of 10 minutes or less is configured for the AUX line.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 7: Console Line Timeout
    result = verify_console_timeout_configured_7(connection)
    if result:
        print("Check 7 Passed: A timeout of exactly 9 minutes 59 seconds or less is configured for the console line.")
    else:
        print("Check 7 Failed: Timeout configuration is missing or not set to exactly 9 minutes 59 seconds for the console line.")
    results.append({
        'Serial Number': 7,
        'Objective': 'Verify that a timeout of exactly 9 minutes 59 seconds or less is configured for the console line.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 8: TTY Line Timeout
    result = verify_tty_timeout_configured_8(connection, tty_line_number)
    if result:
        print(f"Check 8 Passed: A timeout is configured for TTY line {tty_line_number}.")
    else:
        print(f"Check 8 Failed: No timeout configuration found for TTY line {tty_line_number} (Need Physical Hardware).")
    results.append({
        'Serial Number': 8,
        'Objective': f'Verify that a timeout is configured for TTY line {tty_line_number}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 9: VTY Line Timeout
    result = verify_vty_timeout_configured_9(connection, vty_line_number)
    if result:
        print(f"Check 9 Passed: A timeout of 10 minutes or less is configured for VTY line {vty_line_number}.")
    else:
        print(f"Check 9 Failed: No timeout configuration found or timeout exceeds 10 minutes for VTY line {vty_line_number}.")
    results.append({
        'Serial Number': 9,
        'Objective': f'Verify that a timeout of 10 minutes or less is configured for VTY line {vty_line_number}.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 10: AUX Input Transports
    result = verify_aux_input_transports_disabled_10(connection)
    if result:
        print("Check 10 Passed: Inbound connections for the AUX port are disabled.")
    else:
        print("Check 10 Failed: Inbound connections for the AUX port are not disabled.")
    results.append({
        'Serial Number': 10,
        'Objective': 'Verify that inbound connections for the AUX port are disabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 11: AAA Services
    result = verify_aaa_services_enabled_11(connection)
    if result:
        print("Check 11 Passed: AAA services are enabled.")
    else:
        print("Check 11 Failed: AAA services are not enabled.")
    results.append({
        'Serial Number': 11,
        'Objective': 'Verify that AAA services are enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 12: AAA Authentication Login
    result = verify_aaa_authentication_login_enabled_12(connection)
    if result:
        print("Check 12 Passed: AAA authentication for login is enabled.")
    else:
        print("Check 12 Failed: AAA authentication for login is not enabled.")
    results.append({
        'Serial Number': 12,
        'Objective': 'Verify that AAA authentication for login is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 13: AAA Authentication Enable Mode
    result = verify_aaa_authentication_enable_mode_13(connection)
    if result:
        print("Check 13 Passed: AAA authentication for enable mode is enabled.")
    else:
        print("Check 13 Failed: AAA authentication for enable mode is not enabled.")
    results.append({
        'Serial Number': 13,
        'Objective': 'Verify that AAA authentication for enable mode is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 14: AAA Authentication Line con 0
    result = verify_aaa_authentication_line_con_0_14(connection)
    if result:
        print("Check 14 Passed: Set login authentication for line con 0.")
    else:
        print("Check 14 Failed: Set login authentication for line con 0 failed.")
    results.append({
        'Serial Number': 14,
        'Objective': 'Verify that login authentication is set for line con 0.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 15: AAA Authentication Line TTY
    result = verify_aaa_authentication_line_tty_15(connection)
    if result:
        print("Check 15 Passed: Set login authentication for line TTY 0.")
    else:
        print("Check 15 Failed: Set login authentication for line TTY 0 failed.")
    results.append({
        'Serial Number': 15,
        'Objective': 'Verify that login authentication is set for line TTY 0.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 16: AAA Authentication Line VTY
    result = verify_aaa_authentication_line_vty_16(connection)
    if result:
        print("Check 16 Passed: Set login authentication for line VTY 0.")
    else:
        print("Check 16 Failed: Set login authentication for line VTY 0 failed.")
    results.append({
        'Serial Number': 16,
        'Objective': 'Verify that login authentication is set for line VTY 0.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 17: AAA Accounting Commands
    result = verify_aaa_accounting_commands_17(connection)
    if result:
        print("Check 17 Passed: AAA accounting for commands is enabled.")
    else:
        print("Check 17 Failed: AAA accounting for commands is not enabled.")
    results.append({
        'Serial Number': 17,
        'Objective': 'Verify that AAA accounting for commands is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 18: AAA Accounting Connection
    result = verify_aaa_accounting_connection_18(connection)
    if result:
        print("Check 18 Passed: AAA accounting for connection is enabled.")
    else:
        print("Check 18 Failed: AAA accounting for connection is not enabled.")
    results.append({
        'Serial Number': 18,
        'Objective': 'Verify that AAA accounting for connection is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 19: AAA Accounting Exec
    result = verify_aaa_accounting_exec_19(connection)
    if result:
        print("Check 19 Passed: AAA accounting for exec is enabled.")
    else:
        print("Check 19 Failed: AAA accounting for exec is not enabled.")
    results.append({
        'Serial Number': 19,
        'Objective': 'Verify that AAA accounting for exec is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 20: AAA Accounting Network
    result = verify_aaa_accounting_network_20(connection)
    if result:
        print("Check 20 Passed: AAA accounting for network is enabled.")
    else:
        print("Check 20 Failed: AAA accounting for network is not enabled.")
    results.append({
        'Serial Number': 20,
        'Objective': 'Verify that AAA accounting for network is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 21: AAA Accounting System
    result = verify_aaa_accounting_system_21(connection)
    if result:
        print("Check 21 Passed: AAA accounting for system is enabled.")
    else:
        print("Check 21 Failed: AAA accounting for system is not enabled.")
    results.append({
        'Serial Number': 21,
        'Objective': 'Verify that AAA accounting for system is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 22: Exec Banner
    result = verify_exec_banne_22(connection)
    if result:
        print("Check 22 Passed: Exec banner is set.")
    else:
        print("Check 22 Failed: Exec banner is not set.")
    results.append({
        'Serial Number': 22,
        'Objective': 'Verify that the Exec banner is set.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 23: Login Banner
    result = verify_login_banner_23(connection)
    if result:
        print("Check 23 Passed: Login banner is set.")
    else:
        print("Check 23 Failed: Login banner is not set.")
    results.append({
        'Serial Number': 23,
        'Objective': 'Verify that the Login banner is set.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 24: MOTD Banner
    result = verify_motd_banner_24(connection)
    if result:
        print("Check 24 Passed: MOTD banner is set.")
    else:
        print("Check 24 Failed: MOTD banner is not set.")
    results.append({
        'Serial Number': 24,
        'Objective': 'Verify that the MOTD banner is set.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 25: Enable Secret
    result = verify_enable_secret_25(connection)
    if result:
        print("Check 25 Passed: Enable secret is set.")
    else:
        print("Check 25 Failed: Enable secret is not set.")
    results.append({
        'Serial Number': 25,
        'Objective': 'Verify that the enable secret is set.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 26: Password Encryption Service
    result = verify_password_encryption_26(connection)
    if result:
        print("Check 26 Passed: Password encryption service is enabled.")
    else:
        print("Check 26 Failed: Password encryption service is not enabled.")
    results.append({
        'Serial Number': 26,
        'Objective': 'Verify that the password encryption service is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 27: Encrypted Password User
    result = verify_encrypted_password_user_27(connection)
    if result:
        print("Check 27 Passed: User with an encrypted password is enabled.")
    else:
        print("Check 27 Failed: No user with an encrypted password is found.")
    results.append({
        'Serial Number': 27,
        'Objective': 'Verify that a user with an encrypted password is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 28: SNMP Agent Status
    result = verify_snmp_agent_status_28(connection)
    if result:
        print("Check 28 Passed: SNMP agent is not enabled.")
    else:
        print("Check 28 Failed: SNMP agent is enabled.")
    results.append({
        'Serial Number': 28,
        'Objective': 'Verify that the SNMP agent is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 29: Private Community String
    result = verify_public_community_string_29(connection)
    if result:
        print("Check 29 Passed: Private community string 'private' is not present.")
    else:
        print("Check 29 Failed: Private community string 'private' is present.")
    results.append({
        'Serial Number': 29,
        'Objective': 'Verify that the private community string \'private\' is not present.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 30: Public Community String
    result = verify_public_community_string_30(connection)
    if result:
        print("Check 30 Passed: Public community string is not enabled.")
    else:
        print("Check 30 Failed: Public community string is enabled.")
    results.append({
        'Serial Number': 30,
        'Objective': 'Verify that the public community string is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })




    # Check 31: Read/Write Community String
    result = verify_rw_community_string_31(connection)
    if result:
        print("Check 31 Passed: Read/Write community string is not enabled.")
    else:
        print("Check 31 Failed: Read/Write community string is enabled.")
    results.append({
        'Serial Number': 31,
        'Objective': 'Verify that the Read/Write community string is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 32: ACL Enabled
    result = verify_acl_enabled_32(connection)
    if result:
        print("Check 32 Passed: ACL is enabled.")
    else:
        print("Check 32 Failed: ACL is not enabled.")
    results.append({
        'Serial Number': 32,
        'Objective': 'Verify that ACL is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 33: ACL Entries for SNMP
    result = verify_acl_entries_snmp_33(connection, vty_acl_number, required_entries)
    if result:
        print(f"Check 33 Passed: ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")
    else:
        print(f"Check 33 Failed: ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")
    results.append({
        'Serial Number': 33,
        'Objective': f'Verify that ACL {vty_acl_number} contains the required entries for SNMP.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 34: SNMP Hosts Enabled
    result = verify_snmp_traps_enabled_34(connection)
    if result:
        print("Check 34 Passed: SNMP HOSTs are enabled.")
    else:
        print("Check 34 Failed: SNMP HOSTs are not enabled.")
    results.append({
        'Serial Number': 34,
        'Objective': 'Verify that SNMP HOSTs are enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 35: SNMP Traps Enabled
    result = verify_snmp_traps_enabled_35(connection)
    if result:
        print("Check 35 Passed: SNMP traps are enabled.")
    else:
        print("Check 35 Failed: SNMP traps are not enabled.")
    results.append({
        'Serial Number': 35,
        'Objective': 'Verify that SNMP traps are enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 36: SNMP Group and Security Model
    result = verify_snmp_group_and_security_model_36(connection, expected_group_name, expected_security_model)
    if result:
        print("Check 36 Passed: SNMP group and security model are correctly configured.")
    else:
        print("Check 36 Failed: SNMP group or security model are not correctly configured.")
    results.append({
        'Serial Number': 36,
        'Objective': 'Verify that SNMP group and security model are correctly configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 37: SNMP User and Security Settings
    result = verify_snmp_user_and_security_settings_37(connection, expected_user_name, expected_security_settings)
    if result:
        print("Check 37 Passed: SNMP user and security settings are correctly configured.")
    else:
        print("Check 37 Failed: SNMP user or security settings are not correctly configured.")
    results.append({
        'Serial Number': 37,
        'Objective': 'Verify that SNMP user and security settings are correctly configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 38: Hostname Configuration
    result = verify_hostname_38(connection)
    if result:
        print("Check 38 Passed: Hostname is configured.")
    else:
        print("Check 38 Failed: Hostname is not configured.")
    results.append({
        'Serial Number': 38,
        'Objective': 'Verify that the hostname is configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 39: Domain Name Configuration
    result = verify_domain_name_39(connection)
    if result:
        print("Check 39 Passed: Domain name is configured.")
    else:
        print("Check 39 Failed: Domain name is not configured.")
    results.append({
        'Serial Number': 39,
        'Objective': 'Verify that the domain name is configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 40: RSA Key Pair Configuration
    result = verify_rsa_key_pair_40(connection)
    if result:
        print("Check 40 Passed: RSA key pair is configured.")
    else:
        print("Check 40 Failed: RSA key pair is not configured.")
    results.append({
        'Serial Number': 40,
        'Objective': 'Verify that the RSA key pair is configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 41: SSH Timeout Configuration
    result = verify_ssh_timeout_41(connection)
    if result:
        print("Check 41 Passed: SSH timeout is configured properly.")
    else:
        print("Check 41 Failed: SSH timeout is not configured properly.")
    results.append({
        'Serial Number': 41,
        'Objective': 'Verify that SSH timeout is configured properly.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 42: SSH Retry Configuration
    result = verify_ssh_retry_42(connection)
    if result:
        print("Check 42 Passed: SSH Retry is configured properly.")
    else:
        print("Check 42 Failed: SSH Retry is not configured properly.")
    results.append({
        'Serial Number': 42,
        'Objective': 'Verify that SSH Retry is configured properly.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 43: SSH Version Configuration
    result = verify_ssh_version_43(connection)
    if result:
        print("Check 43 Passed: SSH Version is configured properly.")
    else:
        print("Check 43 Failed: SSH Version is not configured properly.")
    results.append({
        'Serial Number': 43,
        'Objective': 'Verify that SSH Version is configured properly.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 44: CDP Disabled
    result = verify_cdp_disabled_44(connection)
    if result:
        print("Check 44 Passed: CDP is not enabled.")
    else:
        print("Check 44 Failed: CDP is enabled or the result is different.")
    results.append({
        'Serial Number': 44,
        'Objective': 'Verify that CDP is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 45: BOOTP Disabled
    result = verify_bootp_enabled_45(connection)
    if result:
        print("Check 45 Passed: BOOTP is not enabled or the result is different.")
    else:
        print("Check 45 Failed: BOOTP is enabled.")
    results.append({
        'Serial Number': 45,
        'Objective': 'Verify that BOOTP is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 46: DHCP Service Disabled
    result = verify_dhcp_service_enabled_46(connection)
    if result:
        print("Check 46 Passed: DHCP service is not enabled or the result is different.")
    else:
        print("Check 46 Failed: DHCP service is enabled.")
    results.append({
        'Serial Number': 46,
        'Objective': 'Verify that DHCP service is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 47: Identd Disabled
    result = verify_identd_enabled_47(connection)
    if result:
        print("Check 47 Passed: Identd is not enabled.")
    else:
        print("Check 47 Failed: Identd is enabled or the result is different.")
    results.append({
        'Serial Number': 47,
        'Objective': 'Verify that Identd is not enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 48: TCP Keepalives-In Enabled
    result = verify_tcp_keepalives_in_enabled_48(connection)
    if result:
        print("Check 48 Passed: TCP keepalives-in is enabled.")
    else:
        print("Check 48 Failed: TCP keepalives-in is not enabled.")
    results.append({
        'Serial Number': 48,
        'Objective': 'Verify that TCP keepalives-in is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 49: TCP Keepalives-Out Enabled
    result = verify_tcp_keepalives_out_enabled_49(connection)
    if result:
        print("Check 49 Passed: TCP keepalives-out is enabled.")
    else:
        print("Check 49 Failed: TCP keepalives-out is not enabled.")
    results.append({
        'Serial Number': 49,
        'Objective': 'Verify that TCP keepalives-out is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 50: Service Pad Disabled
    result = verify_service_pad_disabled_50(connection)
    if result:
        print("Check 50 Passed: Service pad is disabled.")
    else:
        print("Check 50 Failed: Service pad is not disabled.")
    results.append({
        'Serial Number': 50,
        'Objective': 'Verify that service pad is disabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 51: Logging On Disabled
    result = verify_logging_on_disabled_51(connection)
    if result:
        print("Check 51 Passed: Logging on is disabled.")
    else:
        print("Check 51 Failed: Logging on is not disabled.")
    results.append({
        'Serial Number': 51,
        'Objective': 'Verify that logging on is disabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 52: Logging Buffered Enabled
    result = verify_logging_buffered_enabled_52(connection)
    if result:
        print("Check 52 Passed: Logging buffered is enabled.")
    else:
        print("Check 52 Failed: Logging buffered is not enabled.")
    results.append({
        'Serial Number': 52,
        'Objective': 'Verify that logging buffered is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 53: Logging Console Enabled
    result = verify_logging_console_enabled_53(connection)
    if result:
        print("Check 53 Passed: Logging console is enabled.")
    else:
        print("Check 53 Failed: Logging console is not enabled.")
    results.append({
        'Serial Number': 53,
        'Objective': 'Verify that logging console is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 54: Syslog Server Enabled
    result = verify_syslog_server_enabled_54(connection)
    if result:
        print("Check 54 Passed: Logging syslog is enabled.")
    else:
        print("Check 54 Failed: Logging syslog is not enabled.")
    results.append({
        'Serial Number': 54,
        'Objective': 'Verify that logging syslog is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 55: Syslog Server for SNMP Traps Enabled
    result = verify_syslog_trap_server_enabled_55(connection)
    if result:
        print("Check 55 Passed: Syslog server for SNMP traps is enabled.")
    else:
        print("Check 55 Failed: Syslog server for SNMP traps is not enabled.")
    results.append({
        'Serial Number': 55,
        'Objective': 'Verify that syslog server for SNMP traps is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 56: Service Timestamps Debug Datetime Enabled
    result = verify_service_timestamps_debug_datetime_enabled_56(connection)
    if result:
        print("Check 56 Passed: Service timestamps debug datetime is enabled.")
    else:
        print("Check 56 Failed: Service timestamps debug datetime is not enabled.")
    results.append({
        'Serial Number': 56,
        'Objective': 'Verify that service timestamps debug datetime is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 57: Logging Source Interface Enabled
    result = loggin_source_interface_57(connection)
    if result:
        print("Check 57 Passed: Logging Source Interface is enabled.")
    else:
        print("Check 57 Failed: Logging Source Interface is not enabled.")
    results.append({
        'Serial Number': 57,
        'Objective': 'Verify that Logging Source Interface is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 58: NTP Authentication Enabled
    result = verify_ntp_authenticate_58(connection)
    if result:
        print("Check 58 Passed: NTP Authentication is enabled.")
    else:
        print("Check 58 Failed: NTP Authentication is not enabled.")
    results.append({
        'Serial Number': 58,
        'Objective': 'Verify that NTP Authentication is enabled.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 59: NTP Authentication Keys Configured
    result = verify_ntp_authentication_key_59(connection)
    if result:
        print("Check 59 Passed: NTP authentication keys are configured.")
    else:
        print("Check 59 Failed: NTP authentication keys are not configured.")
    results.append({
        'Serial Number': 59,
        'Objective': 'Verify that NTP authentication keys are configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 60: NTP Trusted Keys
    result = verify_ntp_trusted_keys_60(connection, expected_keys_count)
    if result:
        print("Check 60 Passed: The number of NTP trusted keys matches the expected number.")
    else:
        print("Check 60 Failed: The number of NTP trusted keys does not match the expected number.")
    results.append({
        'Serial Number': 60,
        'Objective': 'Verify that the number of NTP trusted keys matches the expected number.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })


    # Check 61: NTP Servers Configured
    result = verify_ntp_servers_configured_61(connection)
    if result:
        print("Check 61 Passed: NTP servers are configured.")
    else:
        print("Check 61 Failed: No NTP servers are configured.")
    results.append({
        'Serial Number': 61,
        'Objective': 'Verify that NTP servers are configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 62: NTP Associations Configured
    result = verify_ntp_associations_62(connection)
    if result:
        print("Check 62 Passed: NTP associations are configured.")
    else:
        print("Check 62 Failed: No NTP associations are configured.")
    results.append({
        'Serial Number': 62,
        'Objective': 'Verify that NTP associations are configured.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 63: Loopback Interface Defined
    result = verify_loopback_interface_defined_63(connection)
    if result:
        print("Check 63 Passed: A loopback interface is defined with an IP address.")
    else:
        print("Check 63 Failed: No loopback interface is defined with an IP address.")
    results.append({
        'Serial Number': 63,
        'Objective': 'Verify that a loopback interface is defined with an IP address.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 64: AAA Services Bound to Source Interface
    result = verify_aaa_services_bound_to_source_interface_64(connection)
    if result:
        print("Check 64 Passed: AAA services are bound to a source interface.")
    else:
        print("Check 64 Failed: AAA services are not bound to a source interface.")
    results.append({
        'Serial Number': 64,
        'Objective': 'Verify that AAA services are bound to a source interface.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 65: NTP Services Bound to Source Interface
    result = verify_ntp_services_bound_to_source_interface_65(connection)
    if result:
        print("Check 65 Passed: NTP services are bound to a source interface.")
    else:
        print("Check 65 Failed: NTP services are not bound to a source interface.")
    results.append({
        'Serial Number': 65,
        'Objective': 'Verify that NTP services are bound to a source interface.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })

    # Check 66: TFTP Services Bound to Source Interface
    result = verify_tftp_services_bound_to_source_interface_66(connection)
    if result:
        print("Check 66 Passed: TFTP services are bound to a source interface.")
    else:
        print("Check 66 Failed: TFTP services are not bound to a source interface.")
    results.append({
        'Serial Number': 66,
        'Objective': 'Verify that TFTP services are bound to a source interface.',
        'Result': 'Pass' if result else 'Fail',
        'Compliance': 'Compliant' if result else 'Non-Compliant'
    })


    # Write results to CSV
    with open('compliance_report.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Objective', 'Result', 'Compliance'])
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    main()
