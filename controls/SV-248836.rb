control 'SV-248836' do
  title 'The OL 8 file system automounter must be disabled.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Note: If the "autofs" service is not installed, this requirement is not applicable.

Verify OL 8 disables the ability to automount devices.

Determine if the automounter service is active with the following command:

$ systemctl is-enabled  autofs
masked

If the returned value is not "masked", "disabled", or "not-found", this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to automount devices.

The "autofs" service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag gid: 'V-248836'
  tag rid: 'SV-248836r1261648_rule'
  tag stig_id: 'OL08-00-040070'
  tag fix_id: 'F-52224r1261647_fix'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('autofs_required') == true
    describe systemd_service('autofs.service') do
      it { should be_running }
      it { should be_enabled }
      it { should be_installed }
    end
  elsif package('autofs').installed?
    describe systemd_service('autofs.service') do
      it { should_not be_running }
      it { should_not be_enabled }
      it { should_not be_installed }
    end
  else
    impact 0.0
    describe 'The autofs service is not installed' do
      skip 'The autofs service is not installed, this control is Not Applicable.'
    end
  end
end
