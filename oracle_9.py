import subprocess
import csv

# Perform checks
file_path = '/etc/ssh/sshd_config'
script_2 = 'script_files/2.sh'
script_3 = 'script_files/3.sh'

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

#MBSS 1
def check_file_permissions(file_path):
    stat_output = run_command(f"stat -Lc '%n %a %u/%U %g/%G' {file_path}")
    expected_output = f"{file_path} 600 0/root 0/root"
    return stat_output == expected_output

#MBSS 2
def ssh_private_key_permissions(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

#MBSS 3
def ssh_public_key_permissions(script_path):
    output = run_command(f"bash {script_path}")
    return 'PASS' in output

#MBSS 4
def check_ssh_access_limited():
    # Run first command
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'"""
    output_1 = run_command(command_1)
    
    # Run second command
    command_2 = "grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    output_2 = run_command(command_2)

    # Check if either output matches the expected patterns
    expected_patterns = ['AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups']
    compliance = any(pattern.lower() in (output_1 + output_2).lower() for pattern in expected_patterns)
    
    return compliance

#MBSS 5
def check_log_level():
    # Command 1: Check the effective LogLevel using sshd -T
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" '
        '| grep -i loglevel'
    )
    command_1_output = run_command(command_1)
    
    # Command 2: Check the LogLevel in the configuration files
    command_2 = (
        'grep -Pi \'^\s*loglevel\' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf '
        '| grep -Evi \'(VERBOSE|INFO)\''
    )
    command_2_output = run_command(command_2)

    # Check if 'loglevel' is present and not commented out in command_1 output
    loglevel_not_commented = any(
        line.strip() and not line.strip().startswith('#') and 'loglevel' in line.lower()
        for line in command_1_output.split('\n')
    )

    # Check if command_2 output is empty (no entries are non-compliant)
    loglevel_compliant = loglevel_not_commented and command_2_output == ''
    
    return loglevel_compliant

#MBSS 6
def check_x11_forwarding():
    # Command 1: Check if X11Forwarding is set correctly in the running SSH configuration
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" | grep -i x11forwarding'
    )
    output_1 = run_command(command_1)
    
    # Check if X11Forwarding is set to 'no'
    x11_forwarding_set = 'x11forwarding no' in output_1.lower()
    
    # Command 2: Check the configuration files for any uncommented X11Forwarding settings
    command_2 = (
        'grep -Pi "^\s*X11Forwarding\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi "no"'
    )
    output_2 = run_command(command_2)
    
    # Ensure that no uncommented X11Forwarding settings are set to anything other than 'no'
    x11_forwarding_compliant = x11_forwarding_set and not output_2.strip()

    return x11_forwarding_compliant

#MBSS 7
def check_max_auth_tries():
    # First, check the effective SSH configuration with sshd -T command
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxauthtries"""
    output_1 = run_command(command_1)

    if not output_1:
        return False, "MaxAuthTries not set"

    try:
        max_auth_tries = int(output_1.split()[1])
        if max_auth_tries > 4:
            return False, f"MaxAuthTries is set to {max_auth_tries}, which is higher than recommended"
    except (IndexError, ValueError):
        return False, "Failed to parse MaxAuthTries value"

    # Now, check for any occurrence of MaxAuthTries greater than 4 in config files
    command_2 = """grep -Pi '^\h*maxauthtries\h+([5-9]|[1-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_2 = run_command(command_2)

    if output_2:
        return False, f"MaxAuthTries value greater than 4 found in configuration files"

    return True, "MaxAuthTries is configured correctly"

# MBSS 8 - Ensure SSH IgnoreRhosts is enabled
def check_ignore_rhosts():
    # Check for IgnoreRhosts in the configuration file
    command_check = """grep -Pi '^IgnoreRhosts' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_check = run_command(command_check)
    return '/etc/ssh/sshd_config:IgnoreRhosts yes' in output_check

#MBSS 9
def check_host_based_authentication():
    # Check for IgnoreRhosts in the configuration file
    command_check = """grep -Pi 'hostbasedauthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"""
    output_check = run_command(command_check)
    return '/etc/ssh/sshd_config:HostbasedAuthentication no' in output_check

#MBSS 10
def check_root_login_disabled():
    # Command to check current PermitRootLogin setting
    command_1 = (
        'sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk \'{print $1}\')" | grep permitrootlogin'
    )
    output_1 = run_command(command_1)
    
    # Check if PermitRootLogin is set to no
    permit_root_login_set = 'permitrootlogin no' in output_1.lower()
    
    # Command to check configuration files for PermitRootLogin
    command_2 = (
        'grep -Pi -- "^\s*PermitRootLogin\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf'
    )
    output_2 = run_command(command_2)
    
    # Check if there are any uncommented PermitRootLogin entries
    permit_root_login_compliant = all(
        line.strip().startswith('#') or 'permitrootlogin no' in line.lower()
        for line in output_2.split('\n') if line.strip()
    )
    
    # Ensure both conditions are met for compliance
    compliance = permit_root_login_set and permit_root_login_compliant
    return compliance

#MBSS 11 - Ensure SSH PermitEmptyPasswords is disabled
def check_permit_empty_passwords():
    # Command to check active configuration (sshd -T output)
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitemptypasswords"""
    output_1 = run_command(command_1)

    # Command to check /etc/ssh/sshd_config content
    command_2 = "grep -Pi '^\\s*PermitEmptyPasswords\\b' /etc/ssh/sshd_config"
    output_2 = run_command(command_2)

    # Logic to determine compliance
    if not output_2:
        # No mention of PermitEmptyPasswords in the config file
        return False

    if '#PermitEmptyPasswords' in output_2:
        # It's commented out in the config file
        return False

    # Check if the active configuration has PermitEmptyPasswords set to 'no'
    if 'permitemptypasswords no' in output_1.lower():
        return True
    
    return False

#MBSS 12
def check_permit_user_environment():
    # Command to check active configuration (sshd -T output)
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permituserenvironment"""
    output_1 = run_command(command_1)

    # Command to check /etc/ssh/sshd_config content
    command_2 = "grep -Pi '^\\s*PermitUserEnvironment\\b' /etc/ssh/sshd_config"
    output_2 = run_command(command_2)

    # Logic to determine compliance
    if not output_2:
        # No mention of PermitUserEnvironment in the config file
        return False

    if '#PermitUserEnvironment' in output_2:
        # It's commented out in the config file
        return False

    # Check if the active configuration has PermitUserEnvironment set to 'no'
    if 'permituserenvironment no' in output_1.lower():
        return True
    
    return False

# MBSS 13 - Check SSH Idle Timeout Interval Compliance
def check_ssh_idle_timeout():
    # Command to check ClientAliveInterval
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientaliveinterval"""
    output_1 = run_command(command_1)
    
    # Command to check ClientAliveCountMax
    command_2 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep clientalivecountmax"""
    output_2 = run_command(command_2)
    
    # Command to check /etc/ssh/sshd_config for ClientAlive settings
    config_check_1 = "grep -Pi '^\\s*ClientAliveInterval\\b' /etc/ssh/sshd_config"
    config_check_2 = "grep -Pi '^\\s*ClientAliveCountMax\\b' /etc/ssh/sshd_config"
    config_output_1 = run_command(config_check_1)
    config_output_2 = run_command(config_check_2)
    
    # Check if both parameters exist in sshd_config
    if '#ClientAliveInterval' in config_output_1 or '#ClientAliveCountMax' in config_output_2:
        return False
    
    # Check if active configuration for ClientAliveInterval and ClientAliveCountMax is compliant
    compliant_interval = 'clientaliveinterval 300' in output_1.lower()
    compliant_countmax = 'clientalivecountmax 3' in output_2.lower()
    
    return compliant_interval and compliant_countmax

# MBSS 14 - Check SSH LoginGraceTime Compliance
def check_ssh_logingracetime():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep logingracetime"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Ei '^\s*LoginGraceTime\s+(0|6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+|[^1]m)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)
    
    if '#LoginGraceTime' in output_1 or config_output:
        return False
    
    return 'logingracetime 60' in output_1.lower()

# MBSS 15 - Check SSH Warning Banner Compliance
def check_ssh_banner():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep banner"""
    output_1 = run_command(command_1)
    
    if '#Banner' in output_1:
        return False
    
    return 'banner /etc/issue.net' in output_1.lower()

# MBSS 16 - Check SSH PAM Compliance
def check_ssh_pam():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i usepam"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Pi '^\\s*UsePAM\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'yes'"
    config_output = run_command(config_check)
    
    if '#UsePAM' in output_1 or config_output:
        return False
    
    return 'usepam yes' in output_1.lower()

# MBSS 17 - Check SSH AllowTcpForwarding Compliance
def check_ssh_tcp_forwarding():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i allowtcpforwarding"""
    output_1 = run_command(command_1)
    
    config_check = "grep -Pi '^\\s*AllowTcpForwarding\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf | grep -Evi 'no'"
    config_output = run_command(config_check)
    
    if '#AllowTcpForwarding' in output_1 or config_output:
        return False
    
    return 'allowtcpforwarding no' in output_1.lower()

# MBSS 18 - Check SSH MaxStartups Compliance
def check_ssh_maxstartups():
    command_1 = """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -i maxstartups"""
    output_1 = run_command(command_1)

    config_check = "grep -Ei '^\\s*MaxStartups\\s+(((1[1-9]|[1-9][0-9][0-9]+):([0-9]+):([0-9]+))|(([0-9]+):(3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):([0-9]+))|(([0-9]+):([0-9]+):(6[1-9]|[7-9][0-9]|[1-9][0-9][0-9]+)))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)

    if '#MaxStartups' in output_1 or config_output:
        return False

    return 'maxstartups 10:30:60' in output_1.lower()

# MBSS 19 - Check SSH MaxSessions Compliance
def check_ssh_maxsessions():
    command_1 = """grep -r -i 'MaxSessions' /etc/ssh/sshd_config"""
    output_1 = run_command(command_1)
    print(output_1)

    config_check = "grep -Ei '^\\s*MaxSessions\\s+(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf"
    config_output = run_command(config_check)
    print(config_output)

    if '#MaxSessions 10' in output_1 or config_output:
        return False
    
    if 'maxsessions 10' in output_1.lower():
        return True

# MBSS 20 - Check Password Creation Requirements Compliance
def check_password_creation_requirements():
    # Commands to check pam_pwquality.so configuration
    pam_pwquality_check = "grep pam_pwquality.so /etc/pam.d/system-auth /etc/pam.d/password-auth"
    pam_pwquality_output = run_command(pam_pwquality_check)

    # Commands to check password length requirements
    minlen_check = "grep ^minlen /etc/security/pwquality.conf"
    minlen_output = run_command(minlen_check)

    # Commands to check password complexity requirements
    minclass_check = "grep ^minclass /etc/security/pwquality.conf"
    minclass_output = run_command(minclass_check)

    # Check pam_pwquality.so settings for retry
    retry_compliant = "retry=3" in pam_pwquality_output.lower()

    # Check if minlen is 14 or more
    minlen_compliant = any(int(line.split('=')[1].strip()) >= 14 for line in minlen_output.splitlines())

    # Check if minclass is 4 or more
    minclass_compliant = any(int(line.split('=')[1].strip()) >= 4 for line in minclass_output.splitlines())

    # Verify all conditions for compliance
    return retry_compliant and minlen_compliant and minclass_compliant

# Perform the check
root_login_compliance = check_root_login_disabled()
results = []


#MBSS 1
file_permissions_compliance = check_file_permissions(file_path)
results.append({
    'Serial Number': 1,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on /etc/ssh/sshd_config is configured.',
    'Comments': 'Premissions are configured' if file_permissions_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if file_permissions_compliance else 'Non-Compliant'
})

#MBSS 2
script_compliance = ssh_private_key_permissions(script_2)
results.append({
    'Serial Number': 2,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on SSH private host key files are configured.',
    'Comments': 'Premissions are configured' if script_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if script_compliance else 'Non-Compliant'
})

#MBSS 3
script_compliance = ssh_public_key_permissions(script_3)
results.append({
    'Serial Number': 3,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure permissions on SSH public host key files are configured.',
    'Comments': 'Premissions are configured' if script_compliance else 'Premissions are not configured',
    'Compliance': 'Compliant' if script_compliance else 'Non-Compliant'
})

#MBSS 4
ssh_access_compliance = check_ssh_access_limited()
results.append({
    'Serial Number': 4,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH access is limited.',
    'Comments': 'SSH access is limited' if ssh_access_compliance else 'SSH access is not limited',
    'Compliance': 'Compliant' if ssh_access_compliance else 'Non-Compliant'
})

#MBSS 5
log_level_compliance = check_log_level()

results.append({
    'Serial Number': 5,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH LogLevel is appropriate level: Verbose',
    'Comments': 'LogLevel is correctly set' if log_level_compliance else 'LogLevel is not correctly set',
    'Compliance': 'Compliant' if log_level_compliance else 'Non-Compliant'
})

x11_forwarding_compliance = check_x11_forwarding()
#MBSS 6
results.append({
    'Serial Number': 6,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH X11 forwarding is disabled.',
    'Comments': 'X11 forwarding is disabled' if x11_forwarding_compliance else 'X11 forwarding is not disabled',
    'Compliance': 'Compliant' if x11_forwarding_compliance else 'Non-Compliant'
})

#MBSS 7
max_auth_tries_compliance, comments = check_max_auth_tries()
results.append({
    'Serial Number': 7,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxAuthTries is set to 4 or less.',
    'Comments': comments,
    'Compliance': 'Compliant' if max_auth_tries_compliance else 'Non-Compliant'
})

#MBSS 8
ignore_rhosts_compliance = check_ignore_rhosts()
results.append({
    'Serial Number': 8,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH IgnoreRhosts is enabled and not commented.',
    'Comments': 'Check Ignore Rhost is set' if ignore_rhosts_compliance else 'Check Ignore Rhost is not set',
    'Compliance': 'Compliant' if ignore_rhosts_compliance else 'Non-Compliant'
})

#MBSS 9
host_based_auth_compliance = check_host_based_authentication()
results.append({
    'Serial Number': 9,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH HostbasedAuthentication is disabled.',
    'Comments': 'HostbasedAuthentication is disabled' if host_based_auth_compliance else 'HostbasedAuthentication is not disabled',
    'Compliance': 'Compliant' if host_based_auth_compliance else 'Non-Compliant'
})

#MBSS 10
root_login_compliance = check_root_login_disabled()
results.append({
    'Serial Number': 10,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH root login is disabled.',
    'Comments': 'Root login is disabled' if root_login_compliance else 'Root login is not disabled',
    'Compliance': 'Compliant' if root_login_compliance else 'Non-Compliant'
})

#MBSS 11
permit_empty_passwords_compliance = check_permit_empty_passwords()
results.append({
    'Serial Number': 11,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PermitEmptyPasswords is disabled.',
    'Comments': 'PermitEmptyPasswords is disabled' if permit_empty_passwords_compliance else 'PermitEmptyPasswords is not disabled or incorrectly configured',
    'Compliance': 'Compliant' if permit_empty_passwords_compliance else 'Non-Compliant'
})

#MBSS 12
permit_user_environment_compliance = check_permit_user_environment()
results.append({
    'Serial Number': 12,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PermitUserEnvironment is disabled.',
    'Comments': 'PermitUserEnvironment is disabled' if permit_user_environment_compliance else 'PermitUserEnvironment is not disabled or incorrectly configured',
    'Compliance': 'Compliant' if permit_user_environment_compliance else 'Non-Compliant'
})

#MBSS 13
ssh_idle_timeout_compliance = check_ssh_idle_timeout()
results.append({
    'Serial Number': 13,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH Idle Timeout Interval is configured.',
    'Comments': 'SSH Idle Timeout Interval is correctly configured' if ssh_idle_timeout_compliance else 'SSH Idle Timeout Interval is not correctly configured',
    'Compliance': 'Compliant' if ssh_idle_timeout_compliance else 'Non-Compliant'
})

#MBSS 14
ssh_logingracetime_compliance = check_ssh_logingracetime()
results.append({
    'Serial Number': 14,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH LoginGraceTime is set to one minute or less.',
    'Comments': 'SSH LoginGraceTime is correctly configured' if ssh_logingracetime_compliance else 'SSH LoginGraceTime is not correctly configured',
    'Compliance': 'Compliant' if ssh_logingracetime_compliance else 'Non-Compliant'
})

#MBSS 15
ssh_banner_compliance = check_ssh_banner()
results.append({
    'Serial Number': 15,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH warning banner is configured.',
    'Comments': 'SSH warning banner is correctly configured' if ssh_banner_compliance else 'SSH warning banner is not correctly configured',
    'Compliance': 'Compliant' if ssh_banner_compliance else 'Non-Compliant'
})

#MBSS 16
ssh_pam_compliance = check_ssh_pam()
results.append({
    'Serial Number': 16,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH PAM is enabled.',
    'Comments': 'SSH PAM is correctly configured' if ssh_pam_compliance else 'SSH PAM is not correctly configured',
    'Compliance': 'Compliant' if ssh_pam_compliance else 'Non-Compliant'
})

#MBSS 17
ssh_tcp_forwarding_compliance = check_ssh_tcp_forwarding()
results.append({
    'Serial Number': 17,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH AllowTcpForwarding is disabled.',
    'Comments': 'SSH AllowTcpForwarding is correctly configured' if ssh_tcp_forwarding_compliance else 'SSH AllowTcpForwarding is not correctly configured',
    'Compliance': 'Compliant' if ssh_tcp_forwarding_compliance else 'Non-Compliant'
})

#MBSS 18
ssh_maxstartups_compliance = check_ssh_maxstartups()
results.append({
    'Serial Number': 18,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxStartups is configured.',
    'Comments': 'SSH MaxStartups is correctly configured' if ssh_maxstartups_compliance else 'SSH MaxStartups is not correctly configured',
    'Compliance': 'Compliant' if ssh_maxstartups_compliance else 'Non-Compliant'
})

#MBSS 19
ssh_maxsessions_compliance = check_ssh_maxsessions()
results.append({
    'Serial Number': 19,
    'Category': 'Access, Authentication and Authorization - Configure SSH server',
    'Objective': 'Ensure SSH MaxSessions is limited to 10 or less.',
    'Comments': 'SSH MaxSessions is correctly configured' if ssh_maxsessions_compliance else 'SSH MaxSessions is not correctly configured',
    'Compliance': 'Compliant' if ssh_maxsessions_compliance else 'Non-Compliant'
})

#MBSS 20
password_creation_compliance = check_password_creation_requirements()
results.append({
    'Serial Number': 20,
    'Category': 'Access, Authentication and Authorization - Configure PAM',
    'Objective': 'Ensure password creation requirements are configured.',
    'Comments': 'Password creation requirements are correctly configured' if password_creation_compliance else 'Password creation requirements are not correctly configured',
    'Compliance': 'Compliant' if password_creation_compliance else 'Non-Compliant'
})

# Print results
for result in results:
    print(f"Check Passed: {result['Objective']} is correctly set." if result['Compliance'] == 'Compliant' else f"Check Failed: {result['Objective']} is not correctly set.")

# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Category', 'Objective', 'Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
