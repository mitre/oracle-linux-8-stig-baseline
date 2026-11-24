control 'SV-284945' do
  title 'Oracle Linux must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Without verification of the security functions, they may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.

Sudo reads from "/etc/sudoers", then form files inside "/etc/sudoers.d/", and within that directory reads in lexicographical order from low to high using a "last match wins" principle. Any options in the last matching rule will override options from earlier matching rules.'
  desc 'check', 'Verify Oracle Linux elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# sudo grep -r sysadm_r /etc/sudoers /etc/sudoers.d
{%designated_group} or {user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r {commands}

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure Oracle Linux to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

# sudo visudo -f /etc/sudoers.d/

Use the following example to build the file in the "/etc/sudoers.d" directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:

{%designated_group} or {user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r {commands}

The following are valid examples of context configurations and can be used as a guide:

%designated_group ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL -- Allowing group to run ALL commands
%designated_group ALL=(ALL) ROLE=sysadm_r TYPE=sysadm_t ALL -- Allowing group to run ALL commands, but order of SELinux entries is changed.
%designated_group ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL, !/bin/su -- Allowing ALL command except /bin/su.
user_name ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL -- Allowing user to run ALL commands
user_name ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r /usr/bin/lsblk, /usr/sbin/alternatives -- Allowing user to only run /usr/bin/lsblk and /usr/sbin/alternatives

Remove any configurations that conflict with the above from the following locations:

/etc/sudoers
/etc/sudoers.d/'
  impact 0.5
  tag check_id: 'C-89514r1208339_chk'
  tag severity: 'medium'
  tag gid: 'V-284945'
  tag rid: 'SV-284945r1208710_rule'
  tag stig_id: 'OL08-00-010451'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-89419r1208709_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  output = command('grep -r sysadm_r /etc/sudoers /etc/sudoers.d').stdout.strip

  describe 'The sudoers SELinux context rule' do
    it 'should match the expected SELinux role and type for privileged access' do
      expect(output).to match(/^\s*%[\w-]+\s+ALL=\(ALL\)\s+TYPE=sysadm_t\s+ROLE=sysadm_r\s+ALL/), 'No matching sudoers rule found that elevates to sysadm_t/sysadm_r'
    end
  end
end
