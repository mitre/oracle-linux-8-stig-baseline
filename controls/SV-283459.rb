control 'SV-283459' do
  title 'The OL 8 lastlog command must have a mode of "0750" or less permissive.'
  desc 'Unauthorized disclosure of the contents of the /var/log/lastlog file can reveal system data to attackers, thus compromising its confidentiality.'
  desc 'check', 'Verify the "lastlog" command has a mode of "0750" or less permissive with the following command: 
 
$ sudo stat -c "%a %n" /usr/bin/lastlog

750  /usr/bin/lastlog

If the "lastlog" command has a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Configure the mode of the "lastlog" command for OL 8 to "0750" with the following command:  

$ sudo chmod 0750 /usr/bin/lastlog'
  impact 0.5
  tag check_id: 'C-88024r1188519_chk'
  tag severity: 'medium'
  tag gid: 'V-283459'
  tag rid: 'SV-283459r1188521_rule'
  tag stig_id: 'OL08-00-020262'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-87929r1188520_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
