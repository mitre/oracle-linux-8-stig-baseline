control 'SV-248573' do
  title 'The OL 8 file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's information system security manager (ISSM)/information system security officer (ISSO) and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.

OL 8 comes with many optional software packages, including the file integrity tool Advanced Intrusion Detection Environment (AIDE). This requirement assumes the use of AIDE; however, a different tool may be used if the requirements are met. Note that AIDE does not have a configuration that will send a notification, so a cron job is recommended that uses the mail application on the system to email the results of the file integrity check."
  desc 'check', 'Verify the operating system routinely checks the baseline configuration for unauthorized changes and notifies the SA when anomalies in the operation of any security functions are discovered.

Check that OL 8 routinely executes a file integrity scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the cron directories for scripts controlling the execution and notification of results of the file integrity application. For example, if AIDE is installed on the system, use the following commands:

To search for an aide script:

$ sudo find /usr/local/bin /root /usr/sbin /usr/bin -type f -name aide

To search for scheduled cron jobs:

$ sudo grep -r aide /etc/cron* /var/spool/cron /etc/anacrontab 2>/dev/null
/etc/cron.daily/aide: /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Verify the contents of the scripts listed in the output and confirm that AIDE is configured to run automatically on at least a weekly basis.

If the file integrity application does not exist, a script file controlling the execution of the integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to run automatically on the system at least weekly and to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel with the use of the cron system.

The following example output is generic. It will set cron to run AIDE daily and to send an email at the completion of the analysis. The file path in the more command is exemplary. Common paths include /etc/cron.d/<filename>, /etc/cron.daily/<filename>, /etc/cron.hourly/<filename>, /etc/cron.weekly/<filename>, or /etc/cron.monthly/<filename>.

$ sudo more /etc/cron.daily/aide

#!/bin/bash
/usr/sbin/aide --check |/bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Note: Per requirement OL08-00-010358, the "mailx" package must be installed on the system to enable email functionality.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag gid: 'V-248573'
  tag rid: 'SV-248573r1134847_rule'
  tag stig_id: 'OL08-00-010360'
  tag fix_id: 'F-51961r1134846_fix'
  tag cci: ['CCI-001744', 'CCI-002699', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 b', 'SI-6 d']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
  describe.one do
    describe file("/etc/cron.daily/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe file("/etc/cron.weekly/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe crontab('root').where { command =~ /#{file_integrity_tool}/ } do
      its('commands.flatten') { should include(match %r{/bin/mail}) }
    end
    if file("/etc/cron.d/#{file_integrity_tool}").exist?
      describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
        its('commands') { should include(match %r{/bin/mail}) }
      end
    end
  end
end
