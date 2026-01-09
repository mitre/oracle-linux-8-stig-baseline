control 'SV-248542' do
  title 'OL 8 operating systems must require authentication upon booting into emergency mode.'
  desc 'If the system does not require valid root authentication before it
boots into emergency or rescue mode, anyone who invokes emergency or rescue
mode is granted privileged access to all files on the system.'
  desc 'check', 'Determine if the system requires authentication for emergency mode with the following command:

$ sudo grep sulogin-shell /usr/lib/systemd/system/emergency.service

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

If the "ExecStart" line is configured for anything other than "/usr/lib/systemd/systemd-sulogin-shell emergency" or is commented out or missing, this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into emergency mode by adding the following line to the "/usr/lib/systemd/system/emergency.service" file:

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-248542'
  tag rid: 'SV-248542r1117265_rule'
  tag stig_id: 'OL08-00-010152'
  tag fix_id: 'F-51930r779191_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('emergency') do
    its('params.ExecStart') { should include '/usr/lib/systemd/systemd-sulogin-shell emergency' }
  end
end
