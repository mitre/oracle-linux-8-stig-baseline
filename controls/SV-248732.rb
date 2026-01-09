control 'SV-248732' do
  title 'OL 8 audit logs must have a mode of "0600" or less permissive to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit OL 8 activity.'
  desc 'check', 'Verify the audit logs have a mode of "0600" or less permissive.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log has a mode of "0600" or less permissive with the following command:

$ sudo stat -c "%a %n" /var/log/audit/audit.log

600 /var/log/audit/audit.log

If the audit log has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct permissive mode with the following command:

$ sudo chmod 0600 [audit_log_file]

Replace "[audit_log_file]" to the correct audit log path. By default, this location is "/var/log/audit/audit.log".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag gid: 'V-248732'
  tag rid: 'SV-248732r958434_rule'
  tag stig_id: 'OL08-00-030070'
  tag fix_id: 'F-52120r779761_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file

  describe file(log_file) do
    it { should_not be_more_permissive_than('0600') }
  end
end
