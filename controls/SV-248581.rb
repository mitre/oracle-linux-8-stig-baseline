control 'SV-248581' do
  title 'OL 8 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify that "/etc/sudoers" has no occurrences of "NOPASSWD".

Check that the "/etc/sudoers" file has no occurrences of "NOPASSWD" by running the following command:

$ sudo grep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/

%admin ALL=(ALL) NOPASSWD: ALL

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the information system security officer (ISSO) as an organizationally defined administrative group using multifactor authentication (MFA), this is a finding.)
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" file with the following command:
$ sudo visudo

Remove any occurrences of "NOPASSWD" tags in the file.

Check the configuration of the /etc/sudoers.d/* files with the following command:
$ sudo grep -ir nopasswd /etc/sudoers.d

Remove any occurrences of "NOPASSWD" tags in the file.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-248581'
  tag rid: 'SV-248581r1101870_rule'
  tag stig_id: 'OL08-00-010380'
  tag fix_id: 'F-51969r860914_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  # TODO: figure out why this .where throws an exception if we don't explicitly filter out nils via 'tags.nil?'
  # ergo shouldn't the filtertable be handling that kind of nil-checking for us?
  failing_results = sudoers(input('sudoers_config_files').join(' ')).rules.where { tags.nil? && (tags || '').include?('NOPASSWD') }

  failing_results = failing_results.where { !input('passwordless_admins').include?(users) } if input('passwordless_admins').nil?

  describe 'Sudoers' do
    it 'should not include any (non-exempt) users with NOPASSWD set' do
      expect(failing_results.users).to be_empty, "NOPASSWD settings found for users:\n\t- #{failing_results.users.join("\n\t- ")}"
    end
  end
end
