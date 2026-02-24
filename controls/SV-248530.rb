control 'SV-248530' do
  title 'All OL 8 remote access methods must be monitored.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that OL 8 monitors all remote access methods.

Check that remote access methods are being logged by running the following command:

$ sudo grep -E '(auth\.\*|authpriv\.\*|daemon\.\*)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:auth.*;authpriv.*;daemon.* /var/log/secure

If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Configure OL 8 to monitor all remote access methods by installing rsyslog with the following command:

$ sudo yum install rsyslog

Add or update the following lines to the "/etc/rsyslog.conf" file:

auth.*;authpriv.*;daemon.* /var/log/secure

The "rsyslog" service must be restarted for the changes to take effect. To restart the "rsyslog" service, run the following command:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-248530'
  tag rid: 'SV-248530r958406_rule'
  tag stig_id: 'OL08-00-010070'
  tag fix_id: 'F-51918r779155_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable; remote access not configured within containerized OL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  rsyslog = file('/etc/rsyslog.conf')

  describe rsyslog do
    it { should exist }
  end

  if rsyslog.exist?
    auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
    authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
    daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

    rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf /etc/rsyslog.d/*.conf')

    describe 'Logged remote access methods' do
      it 'should include auth.*' do
        expect(rsyslog_conf.stdout).to match(auth_pattern), 'auth.* not configured for logging'
      end
      it 'should include authpriv.*' do
        expect(rsyslog_conf.stdout).to match(authpriv_pattern), 'authpriv.* not configured for logging'
      end
      it 'should include daemon.*' do
        expect(rsyslog_conf.stdout).to match(daemon_pattern), 'daemon.* not configured for logging'
      end
    end
  end
end
