control 'SV-248607' do
  title 'The OL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements.'
  desc 'Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*gssapiauthentication'

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, or no output is returned or has not been documented with the information system security officer (ISSO), this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow GSSAPI authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "no":

    GSSAPIAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248607'
  tag rid: 'SV-248607r991589_rule'
  tag stig_id: 'OL08-00-010522'
  tag fix_id: 'F-51995r779386_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  setting = 'GSSAPIAuthentication'
  gssapi_authentication = input('sshd_config_values')
  value = gssapi_authentication[setting]
  openssh_present = package('openssh-server').installed?

  only_if('SSH is not installed on the system; this requirement is Not Applicable', impact: 0.0) {
    openssh_present
  }

  if virtualization.system.eql?('docker')
    describe 'In a container Environment' do
      if package('openssh-server').installed?
        it 'the OpenSSH Server should be installed when allowed in Docker environment' do
          expect(input('allow_container_openssh_server')).to eq(true), 'OpenSSH Server is installed but not approved for the Docker environment'
        end
      else
        it 'the OpenSSH Server is not installed' do
          skip 'This requirement is not applicable as the OpenSSH Server is not installed in the Docker environment.'
        end
      end
    end
  else
    describe 'The OpenSSH Server configuration' do
      it "has the correct #{setting} configuration" do
        expect(sshd_active_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Please ensure it set to '#{value}'."
      end
    end
  end
end
