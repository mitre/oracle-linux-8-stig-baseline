control 'SV-248641' do
  title "All OL 8 local interactive user home directories must be group-owned by the home directory owner's primary group."
  desc 'If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files. Users that share the same group may not be able to access files to which they legitimately should have access.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users is group-owned by that user’s primary GID with the following command.

Note: This may miss local interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory "/home/smithj" is used as an example.

     $ sudo ls -ld $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd)

     drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

Check the user's primary group with the following command:

     $ sudo grep $(grep smithj /etc/passwd | awk -F: '{print $4}') /etc/group

     admin:x:250:smithj,jonesj,jacksons

If the user home directory referenced in "/etc/passwd" is not group-owned by that user’s primary GID, this is a finding.)
  desc 'fix', 'Change the group owner of a local interactive user’s home directory to the group found in "/etc/passwd" using the following command.

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj" and has a primary group of users.

     $ sudo chgrp users /home/smithj'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248641'
  tag rid: 'SV-248641r991589_rule'
  tag stig_id: 'OL08-00-010740'
  tag fix_id: 'F-52029r880566_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_iusers = iuser_entries.entries.reject { |iu|
      file(iu['home']).gid == iu.gid.to_i
    }
    failing_homedirs = failing_iusers.map { |iu| iu['home'] }

    describe 'All non-exempt interactive user account home directories on the system' do
      it 'should be group-owned by the group of the user they are associated with' do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
