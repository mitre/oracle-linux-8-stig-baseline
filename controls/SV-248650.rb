control 'SV-248650' do
  title 'OL 8 must not allow users to override SSH environment variables.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.'
  desc 'check', %q(Verify that unattended or automatic login via SSH is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permituserenvironment'

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure OL 8 to allow the SSH daemon to not allow unattended or automatic login to the system. 
 
Add or edit the following line in the "/etc/ssh/sshd_config" file: 
 
PermitUserEnvironment no 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-52084r951573_chk'
  tag severity: 'high'
  tag gid: 'V-248650'
  tag rid: 'SV-248650r991591_rule'
  tag stig_id: 'OL08-00-010830'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-52038r779515_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
