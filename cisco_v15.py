from netmiko import ConnectHandler #type:ignore
import logging
import re
# Enable logging for debugging
logging.basicConfig(filename='netmiko_debug.log', level=logging.DEBUG)

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

def verify_privilege_level(connection):
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

def verify_ssh_transport(connection):
    command = 'show run | sec vty'
    output = connection.send_command(command)
    lines = output.splitlines()

    transport_input_lines = [line.strip() for line in lines if line.strip().startswith('transport input')]
    
    if not transport_input_lines:
        return False  # No transport input lines found
    
    return len(transport_input_lines) == 1 and transport_input_lines[0] == 'transport input ssh'

def verify_aux_exec_disabled(connection):
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

def verify_acl_entries(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)

vty_acl_number = '10'  # Replace with the actual ACL number
required_entries = ['10', '20', '30']  # List the sequence numbers you want to verify

def verify_acl_set(connection, line_start, line_end, vty_acl_number):
    command = f'show run | sec vty {line_start} {line_end}'
    output_line = connection.send_command(command)
    # Check if 'access-class' is present in the output

    if 'access-class' not in output_line:
        return False

    # Return True if both checks are passed
    return True

# Example usage
line_start = '0'  # Replace with the starting line number
line_end = '4'    # Replace with the ending line number

def verify_timeout_configured(connection):
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

def verify_console_timeout_configured(connection):
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

def verify_tty_timeout_configured(connection, tty_line_number):
    command = f'show line tty {tty_line_number} | begin Timeout'
    output = connection.send_command(command)
    
    # Check if 'exec-timeout' is present in the output
    return 'exec-timeout' in output
tty_line_number = '44' 

def verify_vty_timeout_configured(connection, vty_line_number):
    command = f'show line vty {vty_line_number} | begin Timeout'
    output = connection.send_command(command)
    return 'Idle EXEC' in output

# Example usage
vty_line_number = '0'  # Replace with the actual VTY line number

def verify_aux_input_transports_disabled(connection):
    command = 'show line aux 0 | include input transports'
    output = connection.send_command(command)
        
    # Check if the line contains "Allowed input transports are none"
    expected_transport = 'Allowed input transports are none'
    if expected_transport in output:
        return True
    else:
        return False

def verify_aaa_services_enabled(connection):
    command = 'show running-config | include aaa new-model'
    output = connection.send_command(command)
    return 'aaa new-model' in output

def verify_aaa_authentication_login_enabled(connection):
    command = 'show run | include aaa authentication login'
    output = connection.send_command(command)

    lines = output.splitlines()
    for line in lines:
        if 'aaa authentication login' in line:
            return True
    
    return False

def verify_aaa_authentication_enable_mode(connection):
    command = 'show running-config | include aaa authentication enable'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa authentication enable"
    if 'aaa authentication enable' in output:
        return True
    return False

def verify_aaa_accounting_commands(connection):
    command = 'show running-config | include aaa accounting commands'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting commands"
    if 'aaa accounting commands' in output:
        return True
    return False

def verify_aaa_accounting_connection(connection):
    command = 'show running-config | include aaa accounting connection'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting connection"
    if 'aaa accounting connection' in output:
        return True
    return False

def verify_aaa_accounting_exec(connection):
    command = 'show running-config | include aaa accounting exec'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting connection"
    if 'aaa accounting exec' in output:
        return True
    return False


def verify_aaa_accounting_network(connection):
    command = 'show running-config | include aaa accounting network'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting network"
    if 'aaa accounting network' in output:
        return True
    return False

def verify_aaa_accounting_system(connection):
    command = 'show running-config | include aaa accounting system'
    output = connection.send_command(command)
        
    # Check if the output contains "aaa accounting network"
    if 'aaa accounting system' in output:
        return True
    return False

def verify_exec_banner(connection):
    command = 'show running-config | begin banner exec'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner exec' in output:
        return True
    return False

def verify_login_banner(connection):
    command = 'show running-config | begin banner login'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner login' in output:
        return True
    return False


def verify_motd_banner(connection):
    command = 'show running-config | begin banner motd'
    output = connection.send_command(command)
    
    # Check if the output contains the 'banner exec' section
    if 'banner motd' in output:
        return True
    return False

def verify_enable_secret(connection):
    command = 'show running-config | include enable secret'
    output = connection.send_command(command)
    
    # Check if the output contains 'enable secret'
    if 'enable secret' in output:
        return True
    return False

#####################################################################################

def verify_password_encryption(connection):
    command = 'show running-config | include service password-encryption'
    output = connection.send_command(command)
    
    
    # Check if the output contains 'service password-encryption'
    if 'no service password-encryption' in output:
        return False
    
    if 'service password-encryption' in output:
        return True

def verify_encrypted_password_user(connection):
    command = 'show running-config | include username'
    output = connection.send_command(command)
        
    # Check if any line contains 'secret', indicating an encrypted password
    if any('secret' in line for line in output.splitlines()):
        return True
    return False

def verify_snmp_agent_status(connection):
    command = 'show snmp community'
    output = connection.send_command(command)
    
    # Check if the output contains the phrase "SNMP agent not enabled"
    if "SNMP agent not enabled" in output:
        return True
    return False

def verify_public_community_string(connection):
    command = 'show snmp community'
    output = connection.send_command(command)

    # Check if 'private' is not present in the output
    if "private" not in output:
        return True
    return False

def verify_public_community_string(connection):
    command = 'show snmp community'
    output = connection.send_command(command)
    
    # Check if 'public' is not present in the output
    if "public" not in output:
        return True
    return False

def verify_rw_community_string(connection):
    command = 'show run | incl snmp-server community'
    output = connection.send_command(command)
    
    # Check if ' RW ' is not present in the output
    if ' RW ' not in output:
        return True
    return False

def verify_acl_enabled(connection):

    command = 'show run | incl snmp-server community'
    output = connection.send_command(command)
    
    # Check if the output contains a number after the community string
    if any(char.isdigit() for char in output):
        return True
    return False

def verify_acl_entries_snmp(connection, vty_acl_number, required_entries):
    command = f'show ip access-lists {vty_acl_number}'
    output = connection.send_command(command)
    return all(f'{entry} ' in output for entry in required_entries)

vty_acl_number = '10'  # Replace with the actual ACL number
required_entries = ['10', '20', '30']  # List the sequence numbers you want to verify

def verify_snmp_traps_enabled(connection):
    command = 'show run | incl snmp-server'
    output = connection.send_command(command)
    
    # Check if any SNMP configuration is present in the output
    if 'snmp-server enable traps' in output:
        return True
    return False

def verify_snmp_group_and_security_model(connection, expected_group_name, expected_security_model):
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

def verify_snmp_user_and_security_settings(connection, expected_user_name, expected_security_settings):
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

def verify_hostname(connection):
    command = 'show run | include hostname'
    output = connection.send_command(command)
    
    # Print the command output for debugging
    print("Command Output:\n", output)
    
    # Check if 'hostname' is in the output
    if 'hostname' in output:
        return True
    return False

def verify_domain_name(connection):
    command = 'show run | include ip domain-name'
    output = connection.send_command(command)
    
    # Check if 'ip domain-name' is in the output
    if 'ip domain-name' in output:
        return True
    return False


def verify_rsa_key_pair(connection):
    command = 'show crypto key mypubkey rsa'
    output = connection.send_command(command)
        
    # Check if 'RSA key pair' is in the output
    if 'Usage: General Purpose Key' in output:
        return True
    return False


def verify_ssh_timeout(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if '60 secs' in output:
        return True
    return False

def verify_ssh_retry(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if 'retries: 3' in output:
        return True
    return False


def verify_ssh_version(connection):
    command = 'show ip ssh'
    output = connection.send_command(command)
    
    # Look for 'Timeout' in the output
    if 'version 2.0' in output:
        return True
    return False

def verify_cdp_disabled(connection):
    command = 'show cdp'
    output = connection.send_command(command)
    
    # Check if 'CDP is not enabled' is in the output
    if 'CDP is not enabled' in output:
        return True
    return False

def verify_bootp_enabled(connection):
    command = 'show run | include bootp'
    output = connection.send_command(command)

    # Check if 'no ip bootp server' is not present in the output
    if 'no ip bootp server' not in output:
        return True
    return False

def verify_dhcp_service_enabled(connection):
    command = 'show run | include dhcp'
    output = connection.send_command(command)
        
    # Check if 'no service dhcp' is not present in the output
    if 'no service dhcp' not in output:
        return True
    return False

def verify_identd_enabled(connection):
    command = 'show run | include identd'
    output = connection.send_command(command)
    
    # Check if there is no result for 'identd'
    if 'identd' not in output:
        return True
    return False

def verify_tcp_keepalives_in_enabled(connection):
    command = 'show run | include service tcp'
    output = connection.send_command(command)
    
    # Check if 'service tcp-keepalives-in' is present in the output
    if 'service tcp-keepalives-in' in output:
        return True
    return False

def verify_tcp_keepalives_out_enabled(connection):
    command = 'show run | include service tcp'
    output = connection.send_command(command)
    
    # Check if 'service tcp-keepalives-in' is present in the output
    if 'service tcp-keepalives-out' in output:
        return True
    return False

def verify_service_pad_disabled(connection):
    command = 'show run | include service pad'
    output = connection.send_command(command)
    
    # Check if 'service pad' is absent in the output
    if 'no service pad' in output:
        return True
    return False

def verify_logging_on_disabled(connection):
    command = 'show run | include logging on'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'loggin on' not in output:  # No result returned
        return True
    return False

def verify_logging_buffered_enabled(connection):
    command = 'show run | include logging buffered'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'logging buffered' in output:  # No result returned
        return True
    return False


def verify_logging_console_enabled(connection):
    command = 'show run | include logging console'
    output = connection.send_command(command)

    # Check if 'logging on' is absent in the output
    if 'logging console' in output:  # No result returned
        return True
    return False

def verify_syslog_server_enabled(connection):
    command = 'show run | include logging host'
    output = connection.send_command(command)
    
    # Check if there are one or more IP addresses in the output
    if 'logging host' in output:
        return True
    return 

def verify_syslog_trap_server_enabled(connection):
    command = 'sh log | incl Trap logging'
    output = connection.send_command(command)

    # Check if "level informational" is present in the output
    if "level informational" in output:
        return True
    return False

def verify_service_timestamps_debug_datetime_enabled(connection):
    command = 'sh run | incl service timestamps'
    output = connection.send_command(command)

    # Print the command output for debugging
    print("Command Output:\n", output)

    # Check if the output contains "service timestamps debug datetime"
    if "show-timezone" and "msec" in output:
        return True
    return False

def verify_ntp_authentication_key(connection):
    command = 'show run | include ntp authentication-key'
    output = connection.send_command(command)
    
    # Check if 'ntp authentication-key' is present in the output
    if 'ntp authentication-key' in output:
        return True
    return False

def verify_ntp_trusted_keys(connection, expected_keys_count):
    command = 'show run | include ntp trusted-key'
    output = connection.send_command(command)
    
    # Print the command output for debugging
    print("Command Output:\n", output)
    
    # Count the number of trusted NTP keys in the output
    trusted_keys = [line for line in output.splitlines() if 'ntp trusted-key' in line]
    trusted_keys_count_actual = len(trusted_keys)
    
    # Print the count of trusted keys found
    print(f"Number of NTP trusted keys configured: {trusted_keys_count_actual}")
    
    # Compare the actual count with the expected count
    if trusted_keys_count_actual == expected_keys_count:
        return True
    return False

###############################################################################################

def main():
    connection = connect_to_router()
    enable_mode(connection)  # Enter enable mode

    if verify_privilege_level(connection):
        print("All non-excluded users are set to privilege level 1.")
    else:
        print("There are non-excluded users not set to privilege level 1.")

    if verify_ssh_transport(connection):
        print("SSH is the only transport method for VTY logins.")
    else:
        print("Non-SSH transport methods are configured for VTY logins or 'transport input ssh' is missing.")
    
    if verify_aux_exec_disabled(connection):
        print("The EXEC process for the AUX port is disabled.")
    else:
        print("The EXEC process for the AUX port is not disabled.")

    if verify_acl_entries(connection, vty_acl_number, required_entries):
        print(f"ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")
    else:
        print(f"ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")

    if verify_acl_set(connection, line_start, line_end,vty_acl_number):
        print(f"Access-class is set for VTY lines {line_start} to {line_end}.")
    else:
        print(f"Access-class is not set for VTY lines {line_start} to {line_end}.")

    if verify_timeout_configured(connection):
        print("A timeout of 10 minutes or less is configured for the AUX line.")
    else:
        print("Timeout configuration is missing or exceeds 10 minutes for the AUX line.")

    if verify_console_timeout_configured(connection):
        print("A timeout of exactly 9 minutes 59 seconds or less is configured for the console line.")
    else:
        print("Timeout configuration is missing or not set to exactly 9 minutes 59 seconds for the console line.")

    if verify_tty_timeout_configured(connection, tty_line_number):
        print(f"A timeout is configured for TTY line {tty_line_number}.")
    else:
        print(f"No timeout configuration found for TTY line {tty_line_number}.")
    
    if verify_vty_timeout_configured(connection, vty_line_number):
        print(f"A timeout of 10 minutes or less is configured for VTY line {vty_line_number}.")
    else:
        print(f"No timeout configuration found or timeout exceeds 10 minutes for VTY line {vty_line_number}.")

    if verify_aux_input_transports_disabled(connection):
        print("Inbound connections for the AUX port are disabled.")
    else:
        print("Inbound connections for the AUX port are not disabled.")
    
    if verify_aaa_services_enabled(connection):
        print("AAA services are enabled.")
    else:
        print("AAA services are not enabled.")

    if verify_aaa_authentication_login_enabled(connection):
        print("AAA authentication for login is enabled.")
    else:
        print("AAA authentication for login is not enabled.")
        
    if verify_aaa_authentication_enable_mode(connection):
        print("AAA authentication for enable mode is enabled.")
    else:
        print("AAA authentication for enable mode is not enabled.")
    
    if verify_aaa_accounting_commands(connection):
        print("AAA accounting for commands is enabled.")
    else:
        print("AAA accounting for commands is not enabled.")

    if verify_aaa_accounting_connection(connection):
        print("AAA accounting for connection is enabled.")
    else:
        print("AAA accounting for connection is not enabled.")

    if verify_aaa_accounting_exec(connection):
        print("AAA accounting for exec is enabled.")
    else:
        print("AAA accounting for exec is not enabled.")

    if verify_aaa_accounting_network(connection):
        print("AAA accounting for network is enabled.")
    else:
        print("AAA accounting for network is not enabled.")

    if verify_aaa_accounting_system(connection):
        print("AAA accounting for system is enable.")
    else:
        print("AAA accounting for system is not enable.")

    if verify_exec_banner(connection):
        print("Exec banner is set.")
    else:
        print("Exec banner is not set.")
        
    if verify_login_banner(connection):
        print("Login banner is set.")
    else:
        print("Login banner is not set.")

    if verify_motd_banner(connection):
        print("motd banner is set.")
    else:
        print("motd banner is not set.")

    if verify_enable_secret(connection):
        ("Enable secret is set.")
    else:
        print("Enable secret is not set.")
    ################################################################

    if verify_password_encryption(connection):
        print("Password encryption service is enabled.")
    else:
        print("Password encryption service is not enabled.")

    if verify_encrypted_password_user(connection):
        print("User with an encrypted password is enabled.")
    else:
        print("No user with an encrypted password is found.")

    if verify_snmp_agent_status(connection):
        print("SNMP agent is not enabled.")
    else:
        print("SNMP agent is enabled.")

    if verify_public_community_string(connection):
        print("Public community string private is not present.")
    else:
        print("Public community string private is present.")

    if verify_public_community_string(connection):
        print("Public community string is not enabled.")
    else:
        print("Public community string is enabled.")

    if verify_rw_community_string(connection):
        print("Read/Write community string is not enabled.")
    else:
        print("Read/Write community string is enabled.")

    if verify_acl_enabled(connection):
        print("ACL is enabled.")
    else:
        print("ACL is not enabled.")

    if verify_acl_entries_snmp(connection, vty_acl_number, required_entries):
        print(f"ACL {vty_acl_number} contains the required entries: {', '.join(required_entries)}.")
    else:
        print(f"ACL {vty_acl_number} is missing one or more required entries: {', '.join(required_entries)}.")

    if verify_snmp_traps_enabled(connection):
        print("SNMP traps are enabled.")
    else:
        print("SNMP traps are not enabled.")

    if verify_snmp_group_and_security_model(connection, expected_group_name, expected_security_model):
        print("SNMP group and security model are correctly configured.")
    else:
        print("SNMP group or security model are not correctly configured.")

    if verify_snmp_user_and_security_settings(connection, expected_user_name, expected_security_settings):
        print("SNMP user and security settings are correctly configured.")
    else:
        print("SNMP user or security settings are not correctly configured.")

    if verify_hostname(connection):
        print("Hostname is configured.")
    else:
        print("Hostname is not configured.")

    if verify_domain_name(connection):
        print("Domain name is configured.")
    else:
        print("Domain name is not configured.")

    if verify_rsa_key_pair(connection):
        print("RSA key pair is configured.")
    else:
        print("RSA key pair is not configured.")

    if verify_ssh_timeout(connection):
        print("SSH timeout is configured properly.")
    else:
        print("SSH timeout is not configured properly.")

    if verify_ssh_retry(connection):
        print("SSH Retry is configured properly.")
    else:
        print("SSH Retry is not configured properly.")

    if verify_ssh_version(connection):
        print("SSH Version is configured properly.")
    else:
        print("SSH Version is not configured properly.")

    if verify_cdp_disabled(connection):
        print("CDP is not enabled.")
    else:
        print("CDP is enabled or the result is different.")

    if verify_bootp_enabled(connection):
        print("BOOTP is not enabled or the result is different.")
    else:
        print("BOOTP is enabled.")

    if verify_dhcp_service_enabled(connection):
        print("DHCP service is not enabled or the result is different.")
    else:
        print("DHCP service is enabled.")

    if verify_identd_enabled(connection):
        print("Identd is not enabled.")
    else:
        print("Identd is enabled or the result is different.")

    if verify_tcp_keepalives_in_enabled(connection):
        print("TCP keepalives-in is enabled.")
    else:
        print("TCP keepalives-in is not enabled.")

    if verify_tcp_keepalives_out_enabled(connection):
        print("TCP keepalives-out is enabled.")
    else:
        print("TCP keepalives-out is not enabled.")

    if verify_service_pad_disabled(connection):
        print("Service pad is disabled.")
    else:
        print("Service pad is not disabled.")
    
    if verify_logging_on_disabled(connection):
        print("Logging on is disabled.")
    else:
        print("Logging on is not disabled.")

    if verify_logging_buffered_enabled(connection):
        print("Logging buffered is enabled.")
    else:
        print("Logging buffered is not enabled.")

    if verify_logging_console_enabled(connection):
        print("Logging console is enabled.")
    else:
        print("Logging console is not enabled.")

    if verify_syslog_server_enabled(connection):
        print("Logging syslog is enabled.")
    else:
        print("Logging syslog is not enabled.")

    if verify_syslog_trap_server_enabled(connection):
        print("Syslog server for SNMP traps is enabled.")
    else:
        print("Syslog server for SNMP traps is not enabled.")

    if verify_service_timestamps_debug_datetime_enabled(connection):
        print("Service timestamps debug datetime is enabled.")
    else:
        print("Service timestamps debug datetime is not enabled.")

    if verify_ntp_authentication_key(connection):
        print("NTP authentication keys are configured.")
    else:
        print("NTP authentication keys are not configured.") 

    expected_keys_count = 3  # Replace with the expected number of trusted keys
    if verify_ntp_trusted_keys(connection, expected_keys_count):
        print("The number of NTP trusted keys matches the expected number.")
    else:
        print("The number of NTP trusted keys does not match the expected number.")

#############################################################################
    connection.disconnect()

if __name__ == "__main__":
    main()
