control 'SV-248818' do
  title 'OL 8 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc "If security personnel are not notified immediately when storage volume reaches a maximum of 75 percent utilization, they are unable to plan for audit record storage capacity expansion. The notification can be set to trigger at lower utilization thresholds at the information system security officer's (ISSO's) discretion."
  desc 'check', 'Verify OL 8 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following commands:

$ sudo grep -w space_left /etc/audit/auditd.conf

space_left = 25%

If the value of the "space_left" keyword is not set to 25 percent or greater of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and ISSO. If the "space_left" value is not configured to the value 25 percent or more, this is a finding.

If there is no evidence that real-time alerts are configured on the system, this is a finding.'
  desc 'fix', 'Configure OL 8 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches (at most) 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file.

space_left = 25%'
  impact 0.5
  tag check_id: 'C-52252r1106142_chk'
  tag severity: 'medium'
  tag gid: 'V-248818'
  tag rid: 'SV-248818r1106143_rule'
  tag stig_id: 'OL08-00-030730'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-52206r1101876_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
