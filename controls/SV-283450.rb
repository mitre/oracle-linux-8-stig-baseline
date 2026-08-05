control 'SV-283450' do
  title 'OL 8 IP tunnels must use FIPS 140-3-approved cryptographic algorithms.'
  desc 'Overriding the system crypto policy makes the behavior of the Libreswan service violate expectations, and makes system configuration more fragmented.'
  desc 'check', 'Verify the IPsec service uses the system crypto policy with the following command:

Note: If the IPsec service is not installed, this is not applicable.

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf
/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config

If the IPsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure Libreswan to use the system cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.7
  tag check_id: 'C-88015r1188540_chk'
  tag severity: 'high'
  tag gid: 'V-283450'
  tag rid: 'SV-283450r1188541_rule'
  tag stig_id: 'OL08-00-010186'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-87920r1188427_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  only_if('This control is Not Applicable since the IPsec service is not installed', impact: 0.0) {
    package('libreswan').installed?
  }

  ipsec_includes = command('grep -h include /etc/ipsec.conf /etc/ipsec.d/*.conf 2>/dev/null').stdout.lines.map { |line| line.strip.split.join(' ') }

  describe 'IPsec configuration' do
    it 'includes the Libreswan system crypto policy' do
      expect(ipsec_includes).to include('include /etc/crypto-policies/back-ends/libreswan.config')
    end
  end
end
