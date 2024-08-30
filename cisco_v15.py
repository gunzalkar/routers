import paramiko
import re
import pandas as pd
import sys
import openpyxl

# Router connection details
router_ip = sys.argv[1]
router_username = sys.argv[2]
router_password = sys.argv[3]

# Retrieve running config
def get_router_config(ip, username, password):
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=username, password=password)

        # Execute show run command
        stdin, stdout, stderr = ssh_client.exec_command('show run')
        run_data = stdout.read().decode('utf-8')
        
        # Collecting configurations
        configs = {
            'priv': ssh_client.exec_command('show run | incl privilege')[1].read().decode('utf-8'),
            'vty': ssh_client.exec_command('show run | sec vty')[1].read().decode('utf-8'),
            'aux_run': ssh_client.exec_command('show run | sec aux')[1].read().decode('utf-8'),
            'aux_line': ssh_client.exec_command('show line aux 0 | incl exec')[1].read().decode('utf-8'),
            'acl': ssh_client.exec_command('show access-lists')[1].read().decode('utf-8'),
            'vty_acl': ssh_client.exec_command('show run | sec vty')[1].read().decode('utf-8'),
            'aux_timeout': ssh_client.exec_command('show run | sec line aux 0')[1].read().decode('utf-8'),
            'con_timeout': ssh_client.exec_command('show run | sec line con 0')[1].read().decode('utf-8'),
            'tty_timeout': ssh_client.exec_command('show line tty 0 | begin Timeout')[1].read().decode('utf-8'),
            'vty_timeout': ssh_client.exec_command('show line vty 0 | begin Timeout')[1].read().decode('utf-8'),
            'aux_input': ssh_client.exec_command('show line aux 0 | incl input transports')[1].read().decode('utf-8'),
            'aaa': ssh_client.exec_command('show running-config | incl aaa new-model')[1].read().decode('utf-8'),
            'aaa_auth_login': ssh_client.exec_command('show run | incl aaa authentication login')[1].read().decode('utf-8'),
            'aaa_auth_enable': ssh_client.exec_command('show running-config | incl aaa authentication enable')[1].read().decode('utf-8'),
            'aaa_auth_line': ssh_client.exec_command('show run | sec line | incl login authentication')[1].read().decode('utf-8'),
            'aaa_acc_cmds': ssh_client.exec_command('show run | incl aaa accounting commands')[1].read().decode('utf-8'),
            'aaa_acc_conn': ssh_client.exec_command('show run | incl aaa accounting connection')[1].read().decode('utf-8'),
            'aaa_acc_exec': ssh_client.exec_command('show run | incl aaa accounting exec')[1].read().decode('utf-8'),
            'aaa_acc_net': ssh_client.exec_command('show run | incl aaa accounting network')[1].read().decode('utf-8'),
            'aaa_accounting_sys': ssh_client.exec_command('show running-config | incl aaa accounting system')[1].read().decode('utf-8'),
            'exec_banner': ssh_client.exec_command('show running-config | beg banner exec')[1].read().decode('utf-8'),
            'login_banner': ssh_client.exec_command('show running-config | beg banner login')[1].read().decode('utf-8'),
            'banner': ssh_client.exec_command('show running-config | beg banner motd')[1].read().decode('utf-8'),
            'secret': ssh_client.exec_command('show running-config | incl enable secret')[1].read().decode('utf-8'),
            'service_password_encryption': ssh_client.exec_command('show running-config | incl service password-encryption')[1].read().decode('utf-8'),
            'username_secret': ssh_client.exec_command('show running-config | incl username')[1].read().decode('utf-8'),
            'snmp': ssh_client.exec_command('show snmp community')[1].read().decode('utf-8'),
            'snmp_': ssh_client.exec_command('show running-config | incl snmp-server community')[1].read().decode('utf-8'),
            'snmp_acl': ssh_client.exec_command('show ip access-list 1')[1].read().decode('utf-8'),
            'snmp_trap': ssh_client.exec_command('show run | incl snmp-server')[1].read().decode('utf-8'),
            'snmp_group': ssh_client.exec_command('show snmp group')[1].read().decode('utf-8'),
            'snmp_user': ssh_client.exec_command('show snmp user')[1].read().decode('utf-8'),
            'hostname': ssh_client.exec_command('sh run | incl hostname')[1].read().decode('utf-8'),
            'domain': ssh_client.exec_command('show running-config | incl domain name')[1].read().decode('utf-8'),
            'rsa': ssh_client.exec_command('show crypto key mypubkey rsa')[1].read().decode('utf-8'),
            'ssh': ssh_client.exec_command('show ip ssh')[1].read().decode('utf-8'),
            'ssh_retries': ssh_client.exec_command('show ip ssh')[1].read().decode('utf-8'),
            'ssh_version': ssh_client.exec_command('show ip ssh')[1].read().decode('utf-8'),
            'cdp': ssh_client.exec_command('show cdp')[1].read().decode('utf-8'),
            'bootp': ssh_client.exec_command('show running-config | incl bootp')[1].read().decode('utf-8'),
            'dhcp': ssh_client.exec_command('show running-config | incl dhcp')[1].read().decode('utf-8'),
            'identd': ssh_client.exec_command('show running-config | incl identd')[1].read().decode('utf-8'),
            'service': ssh_client.exec_command('show running-config | incl service')[1].read().decode('utf-8'),
            'logging_on': ssh_client.exec_command('show running-config | incl logging on')[1].read().decode('utf-8'),
            'logging_buffered': ssh_client.exec_command('show running-config | incl logging buffered')[1].read().decode('utf-8'),
            'logging_console': ssh_client.exec_command('show running-config | incl logging console')[1].read().decode('utf-8'),
            'logging_host': ssh_client.exec_command('show log | incl logging host')[1].read().decode('utf-8'),
            'logging_trap': ssh_client.exec_command('show log | incl trap logging')[1].read().decode('utf-8'),
            'service_timestamps': ssh_client.exec_command('show running-config | incl service timestamps')[1].read().decode('utf-8'),
            'logging': ssh_client.exec_command('show running-config | incl logging source')[1].read().decode('utf-8'),
            'ntp_auth': ssh_client.exec_command('show running-config | incl ntp authenticate')[1].read().decode('utf-8'),
            'ntp_key': ssh_client.exec_command('show running-config | incl ntp authentication-key')[1].read().decode('utf-8'),
            'ntp_trusted_key': ssh_client.exec_command('show run | include ntp trusted-key')[1].read().decode('utf-8'),
            'ntp_server_key': ssh_client.exec_command('show run | include ntp server')[1].read().decode('utf-8'),
            'ntp_server_ip': ssh_client.exec_command('sh ntp associations')[1].read().decode('utf-8'),
            'loopback': ssh_client.exec_command('show ip interface brief | include Loopback')[1].read().decode('utf-8'),
            'aaa_source': ssh_client.exec_command('show running-config | include (tacacs source|radius source)')[1].read().decode('utf-8'),
            'ntp_source': ssh_client.exec_command('show running-config | include ntp source')[1].read().decode('utf-8'),
            'tftp_source': ssh_client.exec_command('show running-config | include tftp source-interface')[1].read().decode('utf-8'),
            'ip_source_route': ssh_client.exec_command('show running-config | incl ip source-route')[1].read().decode('utf-8'),
            'proxy_arp': {interface: ssh_client.exec_command(f'show ip interface {interface} | incl proxy-arp')[1].read().decode('utf-8') for interface in re.findall(r'(\S+)\s+[\d\.]+\s+\S+\s+\S+\s+\S+\s+\S+', ssh_client.exec_command('show ip interface brief')[1].read().decode('utf-8'))},
            'tunnel': ssh_client.exec_command('show ip interface brief | incl tunnel')[1].read().decode('utf-8'),
            'urpf': {interface: ssh_client.exec_command(f'show ip interface {interface} | incl verify source')[1].read().decode('utf-8') for interface in re.findall(r'(\S+)\s+[\d\.]+\s+\S+\s+\S+\s+\S+\s+\S+', ssh_client.exec_command('show ip interface brief')[1].read().decode('utf-8'))},
            'acl71': ssh_client.exec_command('show ip access-list')[1].read().decode('utf-8'),
            'interface': ssh_client.exec_command('show run | sec interface')[1].read().decode('utf-8'),
            'key_chain': ssh_client.exec_command('show run | sec key chain')[1].read().decode('utf-8'),
            'eigrp': ssh_client.exec_command('show running-config | sec router eigrp')[1].read().decode('utf-8'),
            'auth_mode': ssh_client.exec_command('show running-config | incl authentication mode')[1].read().decode('utf-8'),
            'ospf': ssh_client.exec_command('show running-config | sec router ospf')[1].read().decode('utf-8'),
            'key_chain_rip': ssh_client.exec_command('show running-config | sec key chain')[1].read().decode('utf-8'),
            'rip': ssh_client.exec_command('show running-config | section router rip')[1].read().decode('utf-8'),
            'bgp': ssh_client.exec_command('show running-config | section router bgp')[1].read().decode('utf-8')
        }

        ssh_client.close()
        return configs
    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials.")
    except paramiko.SSHException as sshException:
        print(f"Unable to establish SSH connection: {sshException}")
    except Exception as e:
        print(f"Operation error: {e}")
    return None

def check_privilege_levels(config_output):
    user_priv_regex = re.compile(r'username (\S+) privilege (\d+)')
    matches = user_priv_regex.findall(config_output)
    users_with_wrong_privileges = [match for match in matches if match[1] != '1']
    return {
        'Control Objective': 'Privilege Levels of Local Users',
        'Compliance Status': 'Complied' if not users_with_wrong_privileges else 'Non-Complied',
        'Comments': 'All users have privilege level 1' if not users_with_wrong_privileges else f"Users with wrong privileges: {users_with_wrong_privileges}",
        
    }

def check_vty_transport(config_output):
    transport_input_regex = re.compile(r'transport input (\S+)')
    matches = transport_input_regex.findall(config_output)
    transport_methods = set(matches)
    complied = transport_methods == {'ssh'}
    return {
        'Control Objective': 'VTY Transport Input Method',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'VTY transport input is correctly set to "ssh" only' if complied else f"VTY transport input methods found: {', '.join(transport_methods)}",
        
    }

def check_aux_no_exec(config_output_run, config_output_line):
    no_exec_in_run = 'no exec' in config_output_run
    no_exec_in_line = 'no exec' in config_output_line
    complied = no_exec_in_run and no_exec_in_line
    return {
        'Control Objective': 'Aux Port EXEC Process',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'EXEC process for aux port is correctly disabled with "no exec"' if complied else 'EXEC process for aux port is not properly disabled',
        
    }

def check_acl(config_output, vty_acl):
    acl_defined = False
    vty_acl_number = None
    acl_regex = re.compile(r'ip access-list (\S+)')
    all_acls = acl_regex.findall(config_output)
    vty_acl_regex = re.compile(r'access-class (\S+) in')
    match = vty_acl_regex.search(vty_acl)
    if match:
        vty_acl_number = match.group(1)
    if vty_acl_number in all_acls:
        acl_defined = True
    return {
        'Control Objective': 'ACL Definitions',
        'Compliance Status': 'Complied' if acl_defined else 'Non-Complied',
        'Comments': 'ACL is defined' if acl_defined else 'ACL is not defined',
        
    }

def check_vty_acl(config_output):
    access_class_regex = re.compile(r'access-class \d+ in')
    complied = bool(access_class_regex.search(config_output))
    return {
        'Control Objective': 'VTY Access-Class Definition',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'VTY access-class is defined' if complied else 'VTY access-class is not defined',
        
    }

def check_aux_timeout(config_output):
    complied = 'exec-timeout' in config_output
    return {
        'Control Objective': 'AUX Timeout',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AUX timeout is defined' if complied else 'AUX timeout is not defined',
        
    }

def check_con_timeout(config_output):
    complied = 'exec-timeout' in config_output
    return {
        'Control Objective': 'Console Timeout',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Console timeout is set' if complied else 'Console timeout is not set',
        
    }

def check_tty_timeout(config_output):
    complied = 'exec-timeout' in config_output
    return {
        'Control Objective': 'TTY Timeout',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'TTY timeout is set' if complied else 'TTY timeout is not set',
        
    }

def check_vty_timeout(config_output):
    complied = 'exec-timeout' in config_output
    return {
        'Control Objective': 'VTY Timeout',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'VTY timeout is set' if complied else 'VTY timeout is not set',
        
    }

def check_aux_input_transport(config_output):
    complied = 'input transports are none' in config_output
    return {
        'Control Objective': 'Aux Port Input Transport',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Aux port input transport is correctly set to "none"' if complied else 'Aux port input transport is not properly set',
        
    }

def check_aaa(config_output):
    complied = 'aaa new-model' in config_output
    return {
        'Control Objective': 'AAA New-Model',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA new-model is enabled' if complied else 'AAA new-model is not enabled',
        
    }

def check_aaa_auth_login(config_output):
    complied = 'aaa authentication login' in config_output
    return {
        'Control Objective': 'AAA Authentication Login',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA authentication for login is enabled' if complied else 'AAA authentication for login is not enabled',
        
    }

def check_aaa_auth_enable(config_output):
    complied = 'aaa authentication enable' in config_output
    return {
        'Control Objective': 'AAA Authentication Enable Mode',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA authentication enable mode is enabled' if complied else 'AAA authentication enable mode is not enabled',
        
    }

def check_aaa_auth_line(config_output):
    complied = 'login authentication' in config_output
    return {
        'Control Objective': 'AAA Authentication for Line Login',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA authentication for line login is enabled' if complied else 'AAA authentication for line login is not enabled',
        
    }

def check_aaa_acc_cmds(config_output):
    complied = 'aaa accounting commands' in config_output
    return {
        'Control Objective': 'AAA Accounting Commands 15',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA accounting commands 15 is configured' if complied else 'AAA accounting commands 15 is not configured',
        
    }

def check_aaa_acc_conn(config_output):
    complied = 'aaa accounting connection' in config_output
    return {
        'Control Objective': 'AAA Accounting Connection',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA accounting for connection is enabled' if complied else 'AAA accounting for connection is not enabled',
        
    }

def check_aaa_acc_exec(config_output):
    complied = 'aaa accounting exec' in config_output
    return {
        'Control Objective': 'AAA Accounting Exec',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA accounting for exec is enabled' if complied else 'AAA accounting for exec is not enabled',
        
    }

def check_aaa_acc_net(config_output):
    complied = 'aaa accounting network' in config_output
    return {
        'Control Objective': 'AAA Accounting Network',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA accounting for network is enabled' if complied else 'AAA accounting for network is not enabled',
        
    }

def check_aaa_accounting(config_output):
    complied = 'aaa accounting system' in config_output
    return {
        'Control Objective': 'AAA Accounting System',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA accounting system is enabled' if complied else 'AAA accounting system is not enabled',
        
    }

def check_exec_banner(config_output):
    complied = 'banner exec' in config_output
    return {
        'Control Objective': 'Exec Banner',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Exec banner is set' if complied else 'Exec banner is not set',
        
    }

def check_login_banner(config_output):
    complied = 'banner login' in config_output
    return {
        'Control Objective': 'Login Banner',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Login banner is set' if complied else 'Login banner is not set',
        
    }

def check_banner(config_output):
    complied = 'banner motd' in config_output
    return {
        'Control Objective': 'Banner MOTD',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Banner MOTD is enabled' if complied else 'Banner MOTD is not enabled',
        
    }

def check_enable_secret(config_output):
    complied = 'enable secret' in config_output
    return {
        'Control Objective': 'Enable Secret',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Enable secret is set' if complied else 'Enable secret is not set',
        
    }

def check_service_password_encryption(config_output):
    complied = 'service password-encryption' in config_output
    return {
        'Control Objective': 'Service Password Encryption',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Service password-encryption is enabled' if complied else 'Service password-encryption is not enabled',
        
    }

def check_username_secret(config_output):
    complied = all('secret' in line for line in config_output.splitlines() if 'username' in line)
    return {
        'Control Objective': 'Username Secret',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Username secret is set for all local users' if complied else 'Username secret is not set for all local users',
        
    }

def check_snmp_disabled(config_output):
    complied = 'SNMP agent not enabled' in config_output
    return {
        'Control Objective': 'SNMP Disabled',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SNMP agent is not enabled' if complied else 'SNMP agent is enabled',
        
    }

def check_snmp_private_unset(config_output):
    complied = 'private' not in config_output
    return {
        'Control Objective': 'SNMP Private Community String',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SNMP private community string is not set' if complied else 'SNMP private community string is set',
        
    }

def check_snmp(config_output):
    unset_public = 'snmp-server community public' not in config_output
    no_rw = not any('snmp-server community' in line and 'RW' in line for line in config_output.splitlines())
    acl_set = all(re.search(r'snmp-server community \S+ \d+', line) for line in config_output.splitlines())
    return {
        'Control Objective': 'SNMP Configuration',
        'Compliance Status': 'Complied' if unset_public and no_rw and acl_set else 'Non-Complied',
        'Comments': 'SNMP configuration is correct' if unset_public and no_rw and acl_set else 'SNMP configuration is not correct',
        
    }

def check_snmp_access_list(config_output):
    complied = bool(re.search(r'access-list 1', config_output))
    return {
        'Control Objective': 'SNMP Access-List',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SNMP access-list 1 is created' if complied else 'SNMP access-list 1 is not created',
        
    }

def check_snmp_server_host(config_output):
    complied = bool(re.search(r'snmp-server host', config_output))
    return {
        'Control Objective': 'SNMP Server Host',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SNMP server host is set' if complied else 'SNMP server host is not set',
        
    }

def check_snmp_enable_traps(config_output):
    complied = bool(re.search(r'snmp-server enable traps snmp', config_output))
    return {
        'Control Objective': 'SNMP Enable Traps',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SNMP enable traps are set' if complied else 'SNMP enable traps are not set',
        
    }

def check_snmp_group(config_output):
    match = re.search(r'groupname: (\S+).*security model: (\S+)', config_output)
    complied = bool(match)
    return {
        'Control Objective': 'SNMP Server Group',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': f"Group Name: {match.group(1)}, Security Model: {match.group(2)}" if complied else 'SNMP server group is not set correctly',
        
    }

def check_snmp_user(config_output):
    match = re.search(r'user: (\S+).*Auth.*Priv.*aes-128', config_output)
    complied = bool(match)
    return {
        'Control Objective': 'SNMP Server User',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': f"User Name: {match.group(1)}, Encryption: AES 128" if complied else 'SNMP server user is not set with AES 128 encryption',
        
    }

def check_hostname(config_output):
    match = re.search(r'hostname (\S+)', config_output)
    complied = bool(match)
    return {
        'Control Objective': 'Hostname',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': f"Hostname: {match.group(1)}" if complied else 'Hostname is not set correctly',
        
    }

def check_domain_name(config_output):
    complied = 'ip domain name' in config_output
    return {
        'Control Objective': 'Domain Name',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Domain name is configured' if complied else 'Domain name is not configured',
        
    }

def check_rsa_key(config_output):
    complied = '2048' in config_output
    return {
        'Control Objective': 'RSA Key Pair',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'RSA key pair with modulus 2048 is configured' if complied else 'RSA key pair with modulus 2048 is not configured',
        
    }

def check_ssh_timeout(config_output):
    complied = 'timeout' in config_output
    return {
        'Control Objective': 'SSH Timeout',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SSH timeout is configured' if complied else 'SSH timeout is not configured',
        
    }

def check_ssh_retries(config_output):
    complied = 'Authentication retries: 3' in config_output
    return {
        'Control Objective': 'SSH Authentication Retries',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SSH authentication retries are configured properly' if complied else 'SSH authentication retries are not configured properly',
        
    }

def check_ssh_version(config_output):
    complied = 'SSH version: 2.0' in config_output
    return {
        'Control Objective': 'SSH Version 2',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'SSH version 2 is configured properly' if complied else 'SSH version 2 is not configured properly',
        
    }

def check_cdp(config_output):
    complied = 'CDP is not enabled' in config_output
    return {
        'Control Objective': 'CDP Disabled',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'CDP is not enabled' if complied else 'CDP is enabled',
        
    }

def check_bootp(config_output):
    complied = 'no ip bootp server' in config_output
    return {
        'Control Objective': 'no ip bootp server',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'BOOTP server is disabled' if complied else 'BOOTP server is enabled',
        
    }

def check_dhcp(config_output):
    complied = 'no service dhcp' not in config_output
    return {
        'Control Objective': 'no service dhcp',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'DHCP service is disabled' if complied else 'DHCP service is enabled',
        
    }

def check_identd(config_output):
    complied = 'no ip identd' not in config_output
    return {
        'Control Objective': 'no ip identd',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Identd service is disabled' if complied else 'Identd service is enabled',
        
    }

def check_tcp_keepalives_in(config_output):
    complied = 'service tcp-keepalives-in' in config_output
    return {
        'Control Objective': 'Service TCP-Keepalives-In',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Service tcp-keepalives-in is enabled' if complied else 'Service tcp-keepalives-in is not enabled',
        
    }

def check_tcp_keepalives_out(config_output):
    complied = 'service tcp-keepalives-out' in config_output
    return {
        'Control Objective': 'Service TCP-Keepalives-Out',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Service tcp-keepalives-out is enabled' if complied else 'Service tcp-keepalives-out is not enabled',
        
    }

def check_no_service_pad(config_output):
    complied = 'no service pad' not in config_output
    return {
        'Control Objective': 'No Service PAD',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'No service pad is disabled' if complied else 'No service pad is not disabled',
        
    }

def check_logging_on(config_output):
    complied = 'logging on' not in config_output
    return {
        'Control Objective': 'Logging On',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging on is enabled' if complied else 'Logging on is not enabled',
        
    }

def check_logging_buffered(config_output):
    complied = 'logging buffered' in config_output
    return {
        'Control Objective': 'Logging Buffered',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging buffered is enabled' if complied else 'Logging buffered is not enabled',
        
    }

def check_logging_console(config_output):
    complied = 'logging console' in config_output
    return {
        'Control Objective': 'Logging Console Critical',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging console critical is enabled' if complied else 'Logging console critical is not enabled',
        
    }

def check_logging_host(config_output):
    complied = 'logging host' in config_output
    return {
        'Control Objective': 'Logging Host',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging host is enabled' if complied else 'Logging host is not enabled',
        
    }

def check_logging_trap(config_output):
    complied = 'level informational' in config_output
    return {
        'Control Objective': 'Logging Trap Informational',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging trap informational is enabled' if complied else 'Logging trap informational is not enabled',
        
    }

def check_service_timestamps(config_output):
    complied = 'service timestamps debug datetime' in config_output
    return {
        'Control Objective': 'Service Timestamps Debug Datetime',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Service timestamps debug datetime is enabled' if complied else 'Service timestamps debug datetime is not enabled',
        
    }

def check_logging_source(config_output):
    complied = 'logging source-interface' in config_output
    return {
        'Control Objective': 'Logging Source Interface',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Logging source interface is set' if complied else 'Logging source interface is not set',
        
    }

def check_ntp_authenticate(config_output):
    complied = 'ntp authenticate' in config_output
    return {
        'Control Objective': 'NTP Authenticate',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP authenticate is set' if complied else 'NTP authenticate is not set',
        
    }

def check_ntp_authentication_key(config_output):
    complied = 'ntp authentication-key' in config_output
    return {
        'Control Objective': 'NTP Authentication-Key',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP authentication-key is set' if complied else 'NTP authentication-key is not set',
        
    }

def check_ntp_trusted_key(config_output):
    complied = 'ntp trusted-key' in config_output
    return {
        'Control Objective': 'NTP Trusted-Key',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP trusted-key is set' if complied else 'NTP trusted-key is not set',
        
    }

def check_ntp_server_key(config_output):
    complied = 'ntp server' in config_output and 'key' in config_output
    return {
        'Control Objective': 'NTP Server Key',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP server key is set' if complied else 'NTP server key is not set',
        
    }

def check_ntp_server_ip(config_output):
    complied = bool(re.search(r'\d+\.\d+\.\d+\.\d+', config_output))
    return {
        'Control Objective': 'NTP Server IP Address',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP server IP address is set' if complied else 'NTP server IP address is not set',
        
    }

def check_loopback(config_output):
    complied = 'Loopback' in config_output
    return {
        'Control Objective': 'Loopback Interface',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'A Loopback interface is defined' if complied else 'No Loopback interface is defined',
        
    }

def check_aaa_source(config_output):
    complied = bool(config_output.strip())
    return {
        'Control Objective': 'AAA Source-Interface',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AAA source-interface is set' if complied else 'AAA source-interface is not set',
        
    }

def check_ntp_source(config_output):
    complied = bool(config_output.strip())
    return {
        'Control Objective': 'NTP Source',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'NTP source-interface is set to Loopback' if complied else 'NTP source-interface is not set to Loopback',
        
    }

def check_tftp_source(config_output):
    complied = bool(config_output.strip())
    return {
        'Control Objective': 'TFTP Source-Interface',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'TFTP source-interface is set to Loopback' if complied else 'TFTP source-interface is not set to Loopback',
        
    }

def check_ip_source_route(config_output):
    complied = 'no ip source-route' in config_output
    return {
        'Control Objective': 'No IP Source-Route',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'IP source-route is disabled' if complied else 'IP source-route is enabled',
        
    }

def check_proxy_arp(config_output):
    results = {}
    for interface, output in config_output.items():
        complied = 'Proxy ARP is disabled' in output
        results[interface] = {
            'Control Objective': f'No IP Proxy-ARP on {interface}',
            'Compliance Status': 'Complied' if complied else 'Non-Complied',
            'Comments': 'Proxy ARP is disabled' if complied else 'Proxy ARP is enabled',
            
        }
    return results

def check_tunnel(config_output):
    complied = 'tunnel' not in config_output
    return {
        'Control Objective': 'No Interface Tunnel',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'No tunnel interfaces are defined' if complied else 'Tunnel interfaces are defined',
        
    }

def check_urpf(config_output):
    results = {}
    for interface, output in config_output.items():
        complied = 'verify source reachable-via' in output
        results[interface] = {
            'Control Objective': f'IP Verify Unicast Source Reachable-via on {interface}',
            'Compliance Status': 'Complied' if complied else 'Non-Complied',
            'Comments': 'uRPF is enabled' if complied else 'uRPF is disabled',
            
        }
    return results

def check_acl(config_output):
    complied = bool(re.search(r'ip access-list extended', config_output))
    return {
        'Control Objective': 'IP Access-List Definitions',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'IP access-list extended is defined' if complied else 'IP access-list extended is not defined',
        
    }

def check_interface_access_group(config_output, external_interface):
    complied = bool(re.search(rf'interface {external_interface}\n.*ip access-group', config_output, re.DOTALL))
    return {
        'Control Objective': f'IP Access-Group on Interface {external_interface}',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': f'IP access-group is applied on interface {external_interface}' if complied else f'IP access-group is not applied on interface {external_interface}',
        
    }

def check_key_chain(config_output):
    complied = 'key chain' in config_output
    return {
        'Control Objective': 'EIGRP Authentication Key Chain',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'EIGRP authentication key chain is defined' if complied else 'EIGRP authentication key chain is not defined',
        
    }

def check_key_string(config_output):
    complied = bool(re.search(r'key chain \w+', config_output))
    return {
        'Control Objective': 'Key-String',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Appropriate key chain is defined' if complied else 'Appropriate key chain is not defined',
        
    }

def check_address_family(config_output):
    complied = bool(re.search(r'address-family ipv4 autonomous-system \d+', config_output))
    return {
        'Control Objective': 'Address-Family IPv4 Autonomous-System',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Appropriate address family is set' if complied else 'Appropriate address family is not set',
        
    }

def check_af_interface(config_output):
    complied = bool(re.search(r'af-interface default', config_output))
    return {
        'Control Objective': 'AF-Interface Default',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'AF-Interface Default is set' if complied else 'AF-Interface Default is not set',
        
    }

def check_auth_key_chain(config_output):
    complied = bool(re.search(r'authentication key-chain \w+', config_output))
    return {
        'Control Objective': 'Authentication Key-Chain',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Appropriate authentication key chain is set' if complied else 'Appropriate authentication key chain is not set',
        
    }

def check_auth_mode(config_output):
    complied = 'ip authentication mode eigrp' in config_output
    return {
        'Control Objective': 'EIGRP Authentication Mode',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'EIGRP authentication mode is set' if complied else 'EIGRP authentication mode is not set',
        
    }

def check_ospf_message_digest(config_output):
    complied = 'authentication message-digest' in config_output
    return {
        'Control Objective': 'OSPF Authentication Message-Digest',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'OSPF authentication message-digest is enabled' if complied else 'OSPF authentication message-digest is not enabled',
        
    }

def check_ospf_md5_key(config_output):
    complied = bool(re.search(r'ip ospf message-digest-key \d+ md5 \S+', config_output))
    return {
        'Control Objective': 'OSPF MD5 Key on Interfaces',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'OSPF MD5 key is defined on the appropriate interfaces' if complied else 'OSPF MD5 key is not defined on the appropriate interfaces',
        
    }

def check_key_chain(config_output):
    complied = bool(re.search(r'key chain \S+', config_output))
    return {
        'Control Objective': 'Key Chain',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Key chain is defined' if complied else 'Key chain is not defined',
        
    }

def check_key(config_output):
    complied = bool(re.search(r'key \d+', config_output))
    return {
        'Control Objective': 'Key',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Key is defined' if complied else 'Key is not defined',
        
    }

def check_key_string(config_output):
    complied = bool(re.search(r'key-string \S+', config_output))
    return {
        'Control Objective': 'Key-String',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'Key-string is defined' if complied else 'Key-string is not defined',
        
    }

def check_rip_auth_key_chain(config_output):
    complied = bool(re.search(r'ip rip authentication key-chain \S+', config_output))
    return {
        'Control Objective': 'IP RIP Authentication Key-Chain',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'IP RIP authentication key-chain is defined' if complied else 'IP RIP authentication key-chain is not defined',
        
    }

def check_rip_auth_mode(config_output):
    complied = bool(re.search(r'ip rip authentication mode \S+', config_output))
    return {
        'Control Objective': 'IP RIP Authentication Mode',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'IP RIP authentication mode is set' if complied else 'IP RIP authentication mode is not set',
        
    }

def check_rip_authentication_mode(config_output):
    complied = 'ip rip authentication mode md5' in config_output
    return {
        'Control Objective': 'RIP Authentication Mode',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'RIP authentication mode is set to md5' if complied else 'RIP authentication mode is not set to md5',
        
    }

def check_bgp_neighbor_password(config_output):
    complied = 'neighbor' in config_output and 'password' in config_output
    return {
        'Control Objective': 'BGP Neighbor Password',
        'Compliance Status': 'Complied' if complied else 'Non-Complied',
        'Comments': 'BGP neighbor password is set' if complied else 'BGP neighbor password is not set',
        
    }

def write_to_excel(compliance_results):
    df = pd.DataFrame(compliance_results)
    df.to_excel('compliance_report.xlsx', index=False)
    print("Compliance report written to 'compliance_report.xlsx'")

def main():
    config_outputs = get_router_config(router_ip, router_username, router_password)
    if config_outputs is None:
        print("Failed to retrieve configurations.")
        return

    compliance_results = []

    # Perform compliance checks
    compliance_results.append(check_privilege_levels(config_outputs['priv']))
    compliance_results.append(check_vty_transport(config_outputs['vty']))
    compliance_results.append(check_aux_no_exec(config_outputs['aux_run'], config_outputs['aux_line']))
    compliance_results.append(check_acl(config_outputs['acl'], config_outputs['vty_acl']))
    compliance_results.append(check_vty_acl(config_outputs['vty_acl']))
    compliance_results.append(check_aux_timeout(config_outputs['aux_timeout']))
    compliance_results.append(check_con_timeout(config_outputs['con_timeout']))
    compliance_results.append(check_tty_timeout(config_outputs['tty_timeout']))
    compliance_results.append(check_vty_timeout(config_outputs['vty_timeout']))
    compliance_results.append(check_aux_input_transport(config_outputs['aux_input']))
    compliance_results.append(check_aaa(config_outputs['aaa']))
    compliance_results.append(check_aaa_auth_login(config_outputs['aaa_auth_login']))
    compliance_results.append(check_aaa_auth_enable(config_outputs['aaa_auth_enable']))
    compliance_results.append(check_aaa_auth_line(config_outputs['aaa_auth_line']))
    compliance_results.append(check_aaa_acc_cmds(config_outputs['aaa_acc_cmds']))
    compliance_results.append(check_aaa_acc_conn(config_outputs['aaa_acc_conn']))
    compliance_results.append(check_aaa_acc_exec(config_outputs['aaa_acc_exec']))
    compliance_results.append(check_aaa_acc_net(config_outputs['aaa_acc_net']))
    compliance_results.append(check_aaa_accounting(config_outputs['aaa_accounting_sys']))
    compliance_results.append(check_exec_banner(config_outputs['exec_banner']))
    compliance_results.append(check_login_banner(config_outputs['login_banner']))
    compliance_results.append(check_banner(config_outputs['banner']))
    compliance_results.append(check_enable_secret(config_outputs['secret']))
    compliance_results.append(check_service_password_encryption(config_outputs['service_password_encryption']))
    compliance_results.append(check_username_secret(config_outputs['username_secret']))
    compliance_results.append(check_snmp_disabled(config_outputs['snmp']))
    compliance_results.append(check_snmp_private_unset(config_outputs['snmp']))
    compliance_results.append(check_snmp(config_outputs['snmp_']))
    compliance_results.append(check_snmp_access_list(config_outputs['snmp_acl']))
    compliance_results.append(check_snmp_server_host(config_outputs['snmp_trap']))
    compliance_results.append(check_snmp_enable_traps(config_outputs['snmp_trap']))
    compliance_results.append(check_snmp_group(config_outputs['snmp_group']))
    compliance_results.append(check_snmp_user(config_outputs['snmp_user']))
    compliance_results.append(check_hostname(config_outputs['hostname']))
    compliance_results.append(check_domain_name(config_outputs['domain']))
    compliance_results.append(check_rsa_key(config_outputs['rsa']))
    compliance_results.append(check_ssh_timeout(config_outputs['ssh']))
    compliance_results.append(check_ssh_retries(config_outputs['ssh_retries']))
    compliance_results.append(check_ssh_version(config_outputs['ssh_version']))
    compliance_results.append(check_cdp(config_outputs['cdp']))
    compliance_results.append(check_bootp(config_outputs['bootp']))
    compliance_results.append(check_dhcp(config_outputs['dhcp']))
    compliance_results.append(check_identd(config_outputs['identd']))
    compliance_results.append(check_tcp_keepalives_in(config_outputs['service']))
    compliance_results.append(check_tcp_keepalives_out(config_outputs['service']))
    compliance_results.append(check_no_service_pad(config_outputs['service']))
    compliance_results.append(check_logging_on(config_outputs['logging_on']))
    compliance_results.append(check_logging_buffered(config_outputs['logging_buffered']))
    compliance_results.append(check_logging_console(config_outputs['logging_console']))
    compliance_results.append(check_logging_host(config_outputs['logging_host']))
    compliance_results.append(check_logging_trap(config_outputs['logging_trap']))
    compliance_results.append(check_service_timestamps(config_outputs['service_timestamps']))
    compliance_results.append(check_logging_source(config_outputs['logging']))
    compliance_results.append(check_ntp_authenticate(config_outputs['ntp_auth']))
    compliance_results.append(check_ntp_authentication_key(config_outputs['ntp_key']))
    compliance_results.append(check_ntp_trusted_key(config_outputs['ntp_trusted_key']))
    compliance_results.append(check_ntp_server_key(config_outputs['ntp_server_key']))
    compliance_results.append(check_ntp_server_ip(config_outputs['ntp_server_ip']))
    compliance_results.append(check_loopback(config_outputs['loopback']))
    compliance_results.append(check_aaa_source(config_outputs['aaa_source']))
    compliance_results.append(check_ntp_source(config_outputs['ntp_source']))
    compliance_results.append(check_tftp_source(config_outputs['tftp_source']))
    compliance_results.append(check_ip_source_route(config_outputs['ip_source_route']))

    proxy_arp_status = check_proxy_arp(config_outputs['proxy_arp'])
    for interface_result in proxy_arp_status.values():
        compliance_results.append(interface_result)

    compliance_results.append(check_tunnel(config_outputs['tunnel']))

    urpf_status = check_urpf(config_outputs['urpf'])
    for interface_result in urpf_status.values():
        compliance_results.append(interface_result)

    compliance_results.append(check_acl(config_outputs['acl71']))

    external_interface = "GigabitEthernet0/0"  # external interface
    compliance_results.append(check_interface_access_group(config_outputs['interface'], external_interface))

    compliance_results.append(check_key_chain(config_outputs['key_chain']))
    compliance_results.append(check_key_string(config_outputs['key_chain']))
    compliance_results.append(check_address_family(config_outputs['eigrp']))
    compliance_results.append(check_af_interface(config_outputs['eigrp']))
    compliance_results.append(check_auth_key_chain(config_outputs['eigrp']))
    compliance_results.append(check_auth_mode(config_outputs['auth_mode']))
    compliance_results.append(check_ospf_message_digest(config_outputs['ospf']))
    compliance_results.append(check_ospf_md5_key(config_outputs['interfaces']))
    compliance_results.append(check_key_chain(config_outputs['key_chain_rip']))
    compliance_results.append(check_key(config_outputs['key_chain_rip']))
    compliance_results.append(check_key_string(config_outputs['key_chain_rip']))
    compliance_results.append(check_rip_auth_key_chain(config_outputs['interfaces']))
    compliance_results.append(check_rip_auth_mode(config_outputs['interfaces']))
    compliance_results.append(check_rip_authentication_mode(config_outputs['rip']))
    compliance_results.append(check_bgp_neighbor_password(config_outputs['bgp']))

    # Write results to Excel
    write_to_excel(compliance_results)

    control_objectives_list = [
        "Set 'privilege 1' for local users",
        "Set 'transport input ssh' for 'line vty' connections",
        "Set 'no exec' for 'line aux 0'",
        "Create 'access-list' for use with 'line vty'",
        "Set 'access-class' for 'line vty'",
        "Set 'exec-timeout' to less than or equal to 10 minutes for 'line aux 0'",
        "Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0'",
        "Set 'exec-timeout' less than or equal to 10 minutes 'line tty'",
        "Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'",
        "Set 'transport input none' for 'line aux 0'",
        "Enable 'aaa new-model'",
        "Enable 'aaa authentication login'",
        "Enable 'aaa authentication enable default'",
        "Set 'login authentication for 'line con 0'",
        "Set 'login authentication for 'line tty'",
        "Set 'login authentication for 'line vty'",
        "Set 'aaa accounting' to log all privileged use commands using 'commands 15'",
        "Set 'aaa accounting connection'",
        "Set 'aaa accounting exec'",
        "Set 'aaa accounting network'",
        "Set 'aaa accounting system'",
        "Set the 'banner-text' for 'banner exec'",
        "Set the 'banner-text' for 'banner login'",
        "Set the 'banner-text' for 'banner motd'",
        "Set 'password' for 'enable secret'",
        "Enable 'service password-encryption'",
        "Set 'username secret' for all local users",
        "Set 'no snmp-server' to disable SNMP when unused",
        "Unset 'private' for 'snmp-server community'",
        "Unset 'public' for 'snmp-server community'",
        "Do not set 'RW' for any 'snmp-server community'",
        "Set the ACL for each 'snmp-server community'",
        "Create an 'access-list' for use with SNMP",
        "Set 'snmp-server host' when using SNMP",
        "Set 'snmp-server enable traps snmp'",
        "Set 'priv' for each 'snmp-server group' using SNMPv3",
        "Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3",
        "Set the 'hostname'",
        "Set the 'ip domain name'",
        "Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
        "Set 'seconds' for 'ip ssh timeout'",
        "Set maximimum value for 'ip ssh authentication-retries'",
        "Set version 2 for 'ip ssh version'",
        "Set 'no cdp run'",
        "Set 'no ip bootp server'",
        "Set 'no service dhcp'",
        "Set 'no ip identd'",
        "Set 'service tcp-keepalives-in'",
        "Set 'service tcp-keepalives-out'",
        "Set 'no service pad'",
        "Set 'logging on'",
        "Set 'buffer size' for 'logging buffered'",
        "Set 'logging console critical'",
        "Set IP address for 'logging host'",
        "Set 'logging trap informational'",
        "Set 'service timestamps debug datetime'",
        "Set 'logging source interface'",
        "Set 'ntp authenticate'",
        "Set 'ntp authentication-key'",
        "Set the 'ntp trusted-key'",
        "Set 'key' for each 'ntp server'",
        "Set 'ip address' for 'ntp server'",
        "Create a single 'interface loopback'",
        "Set AAA 'source-interface'",
        "Set 'ntp source' to Loopback Interface",
        "Set 'ip tftp source-interface' to the Loopback Interface",
        "Set 'no ip source-route'",
        "Set 'no ip proxy-arp'",
        "Set 'no interface tunnel'",
        "Set 'ip verify unicast source reachable-via'",
        "Set 'ip access-list extended' to Forbid Private Source Addresses from External Networks",
        "Set inbound 'ip access-group' on the External Interface",
        "Require EIGRP Authentication if Protocol is Used",
        "Set 'key'",
        "Set 'key-string'",
        "Set 'address-family ipv4 autonomous-system'",
        "Set 'af-interface default'",
        "Set 'authentication key-chain'",
        "Set 'authentication mode md5' #",
        "Set 'ip authentication key-chain eigrp'",
        "Set 'ip authentication mode eigrp'",
        "Set 'authentication message-digest' for OSPF area",
        "Set 'ip ospf message-digest-key md5'",
        "Set 'key chain'",
        "Set 'key'",
        "Set 'key-string'",
        "Set 'ip rip authentication key-chain'",
        "Set 'ip rip authentication mode' to 'md5'",
        "Set 'neighbor password'"
    ]

    # Read existing Excel file
    excel_file = 'compliance_report.xlsx'  # Replace with your Excel file path
    df = pd.read_excel(excel_file)

    # Insert a new column 'S.No' with serial numbers starting from 1
    df.insert(0, 'S.No', range(1, 1 + len(df)))

    # Replace the existing values in the second column with control_objectives_list
    df.iloc[:, 1] = control_objectives_list[:len(df)]

    # Write back to Excel
    output_file = 'compliance_report.xlsx'  # Replace with your desired output file path
    df.to_excel(output_file, index=False)

    #print(f"Processed {len(df)} rows. Output written to {output_file}")


if __name__ == "__main__":
    main()
