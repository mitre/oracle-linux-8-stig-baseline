control 'SV-248871' do
  title 'OL 8 must disable the systemd Ctrl-Alt-Delete burst key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify OL 8 is not configured to reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ sudo grep -iR CtrlAltDelBurstAction /etc/systemd/system*
/etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction:CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none" or is commented out or missing, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:

If no drop file exists, create one with the following command:

$ sudo mkdir -p /etc/systemd/system.conf.d && sudo vi /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction

Edit the file to contain the setting by adding the following text:

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.5
  tag check_id: 'C-52305r1155542_chk'
  tag severity: 'medium'
  tag gid: 'V-248871'
  tag rid: 'SV-248871r1156667_rule'
  tag stig_id: 'OL08-00-040172'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52259r1155543_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/systemd/system.conf') do
    its('Manager') { should include('CtrlAltDelBurstAction' => 'none') }
  end
end
