control 'SV-248804' do
  title 'OL 8 must allocate an "audit_backlog_limit" of sufficient size to capture processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Allocating an "audit_backlog_limit" of sufficient size is critical in maintaining a stable boot process. With an insufficient limit allocated, the system is susceptible to boot failures and crashes.'
  desc 'check', 'Verify OL 8 allocates a sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following commands:

$ sudo grub2-editenv list | grep audit

kernelopts=root=/dev/mapper/ol-root ro crashkernel=auto resume=/dev/mapper/ol-swap rd.lvm.lv=ol/root rd.lvm.lv=ol/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "audit_backlog_limit" entry does not equal "8192" or larger, is missing, or the line is commented out, this is a finding.

Verify "audit_backlog_limit" is set to persist in kernel updates:

$ sudo grep audit /etc/default/grub

GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"

If "audit_backlog_limit" is not set to "8192" or larger or is missing or commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to allocate sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args="audit_backlog_limit=8192"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"

If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient space will need be to be created.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag gid: 'V-248804'
  tag rid: 'SV-248804r958412_rule'
  tag stig_id: 'OL08-00-030602'
  tag fix_id: 'F-52192r779977_fix'
  tag cci: ['CCI-001849', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-4', 'AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_config = command('grub2-editenv - list').stdout
  kernelopts = parse_config(grub_config)['kernelopts'].to_s.strip.gsub(' ', "\n")
  grub_cmdline_linux = parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX'].to_s.strip.gsub(' ', "\n").gsub('"',
                                                                                                                    '')

  expected_backlog_limit = input('expected_backlog_limit')

  describe 'kernelopts' do
    subject { parse_config(kernelopts) }
    its('audit_backlog_limit') { should cmp >= expected_backlog_limit }
  end

  describe 'persistant kernelopts' do
    subject { parse_config(grub_cmdline_linux) }
    its('audit_backlog_limit') { should cmp >= expected_backlog_limit }
  end
end
