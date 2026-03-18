control 'SV-248764' do
  title 'OL 8 must generate audit records for any use of the "semanage" command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. The "semanage" command is used to configure certain elements of SELinux policy without requiring modification to or recompilation from policy sources.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.'
  desc 'check', 'Verify if OL 8 is configured to audit the execution of the "semanage" command by running the following command:

$ sudo grep -w semanage /etc/audit/audit.rules

a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return all lines or the lines are commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure OL 8 to audit the execution of the "semanage" command by adding or updating the following lines to "/etc/audit/rules.d/audit.rules":

a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-52198r779856_chk'
  tag severity: 'medium'
  tag gid: 'V-248764'
  tag rid: 'SV-248764r958442_rule'
  tag stig_id: 'OL08-00-030313'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-52152r779857_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

  audit_command = '/usr/sbin/semanage'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
