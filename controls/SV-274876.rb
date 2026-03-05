control 'SV-274876' do
  title 'OL 8  must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user and must have the permissions 755 or more restrictive and should have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify that OL 8 is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
auditctl -w /etc/cron.d/ -p wa -k cronjobs
auditctl -w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78977r1101881_chk'
  tag severity: 'medium'
  tag gid: 'V-274876'
  tag rid: 'SV-274876r1106141_rule'
  tag stig_id: 'OL08-00-030645'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-78882r1101882_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

cron_paths = ['/etc/cron.d', '/var/spool/cron']

  describe 'Cron auditing configuration' do
    
    cron_paths.each do |cron_path|
      it "#{cron_path} is audited with correct permissions and key" do
        audit_rule = auditd.file(cron_path)
        expect(audit_rule).to exist
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.key.uniq).to include('cronjobs')
      end
    end
  end
end
