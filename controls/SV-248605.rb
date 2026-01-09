control 'SV-248605' do
  title "The OL 8 SSH daemon must not allow authentication using known host's authentication."
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow authentication using known host’s authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ignoreuserknownhosts'

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known host’s authentication. 
 
Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes": 
 
IgnoreUserKnownHosts yes 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-52039r951565_chk'
  tag severity: 'medium'
  tag gid: 'V-248605'
  tag rid: 'SV-248605r991589_rule'
  tag stig_id: 'OL08-00-010520'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51993r779380_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
