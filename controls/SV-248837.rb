control 'SV-248837' do
  title 'OL 8 must be configured to disable the ability to use USB mass storage devices.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Verify the operating system disables the ability to load the USB Storage kernel module.

     $ sudo grep -r usb-storage /etc/modprobe.d/* | grep -i "/bin/false"
     install usb-storage /bin/false

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Determine if USB mass storage is disabled with the following command:

     $ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" | grep -v "^#"
     /etc/modprobe.d/blacklist.conf:blacklist usb-storage

If the command does not return any output or the output is not "blacklist usb-storage" and use of USB storage devices is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable the ability to use the USB Storage kernel module and to use USB mass storage devices.

     $ sudo vi /etc/modprobe.d/blacklist.conf

Add or update the lines:

     install usb-storage /bin/false
     blacklist usb-storage

Reboot the system for the settings to take effect.'
  impact 0.5
  tag check_id: 'C-52271r986385_chk'
  tag severity: 'medium'
  tag gid: 'V-248837'
  tag rid: 'SV-248837r986386_rule'
  tag stig_id: 'OL08-00-040080'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-52225r943088_fix'
  tag 'documentable'
  tag cci: ['CCI-000778', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  if input('usb_storage_required') == true
    describe kernel_module('usb_storage') do
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
  else
    describe kernel_module('usb_storage') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
