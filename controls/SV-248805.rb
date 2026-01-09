control 'SV-248805' do
  title 'OL 8 must enable Linux audit logging for the USBGuard daemon.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify OL 8 enables Linux audit logging of the USBGuard daemon with the following commands.

Note: If the USBGuard daemon is not installed and enabled, this requirement is not applicable.

$ sudo grep -i auditbackend /etc/usbguard/usbguard-daemon.conf

AuditBackend=LinuxAudit

If the "AuditBackend" entry does not equal "LinuxAudit", is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enable Linux audit logging of the USBGuard daemon by adding or modifying the following line in "/etc/usbguard/usbguard-daemon.conf":

AuditBackend=LinuxAudit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-248805'
  tag rid: 'SV-248805r991579_rule'
  tag stig_id: 'OL08-00-030603'
  tag fix_id: 'F-52193r779980_fix'
  tag cci: ['CCI-000169', 'CCI-000172']
  tag nist: ['AU-12 a', 'AU-12 c']
  tag 'host'

  is_virtualized_system_no_usb_devices = input('is_virtualized_system_no_usb_devices')

  if is_virtualized_system_no_usb_devices
    impact 0.0
    describe 'The system is a virtual machine with no virtual or physical USB peripherals attached' do
      skip 'The system is a virtual machine with no virtual or physical USB peripherals attached, this control is Not Applicable.'
    end
  elsif !(package('usbguard').installed? && service('usbguard').enabled?)
    # Control is Not Applicable if usbguard is not installed and enabled
    impact 0.0
    describe 'The USBGuard service is not installed and enabled' do
      skip 'The USBGuard service is not installed and enabled, this control is Not Applicable.'
    end
  else
    # Check if usbguard is conducting audits
    describe parse_config_file('/etc/usbguard/usbguard-daemon.conf') do
      its('AuditBackend') { should cmp 'LinuxAudit' }
    end
  end
end
