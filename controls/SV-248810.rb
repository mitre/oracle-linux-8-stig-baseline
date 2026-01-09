control 'SV-248810' do
  title 'OL 8 must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include but are not limited to vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools to provide the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools.

Check the selection lines to ensure AIDE is configured to add/check with the following command:

     $ sudo grep -E '(\\/usr\\/sbin\\/(audit|au|rsys))' /etc/aide.conf

     /usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512
     /usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

If any of the audit tools listed above do not have an appropriate selection line, this is a finding."
  desc 'fix', 'Add or update the following lines to "/etc/aide.conf" to protect the integrity of the audit tools.

# Audit Tools
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag gid: 'V-248810'
  tag rid: 'SV-248810r991567_rule'
  tag stig_id: 'OL08-00-030650'
  tag fix_id: 'F-52198r833240_fix'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = %w[/usr/sbin/auditctl
                   /usr/sbin/auditd
                   /usr/sbin/ausearch
                   /usr/sbin/aureport
                   /usr/sbin/autrace
                   /usr/sbin/rsyslogd
                   /usr/sbin/augenrules]

  if package('aide').installed?
    audit_tools.each do |tool|
      describe "selection_line: #{tool}" do
        subject { aide_conf.where { selection_line.eql?(tool) } }
        its('rules.flatten') { should include 'p' }
        its('rules.flatten') { should include 'i' }
        its('rules.flatten') { should include 'n' }
        its('rules.flatten') { should include 'u' }
        its('rules.flatten') { should include 'g' }
        its('rules.flatten') { should include 's' }
        its('rules.flatten') { should include 'b' }
        its('rules.flatten') { should include 'acl' }
        its('rules.flatten') { should include 'xattrs' }
        its('rules.flatten') { should include 'sha512' }
      end
    end
  else
    describe 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE)' do
      skip 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE), manual review is required.'
    end
  end
end
