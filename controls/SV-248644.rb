control 'SV-248644' do
  title 'All OL 8 local interactive user accounts must be assigned a home directory upon creation.'
  desc 'If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify all local interactive users on OL 8 are assigned a home directory upon creation with the following command:

$ sudo grep -i create_home /etc/login.defs

CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248644'
  tag rid: 'SV-248644r991589_rule'
  tag stig_id: 'OL08-00-010760'
  tag fix_id: 'F-52032r779497_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('CREATE_HOME') { should eq 'yes' }
  end
end
