control 'SV-283444' do
  title 'OL 8 must have the crypto-policies package installed.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Using weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

'
  desc 'check', 'Verify the OL 8 crypto-policies package is installed with the following command:

$ dnf list --installed crypto-policies
Installed Packages
crypto-policies.noarch                           20230731-1.git3177e06.el8                            @ol8_baseos_latest

If the crypto-policies package is not installed, this is a finding.'
  desc 'fix', 'Install the crypto-policies package with the following command:

$ sudo dnf -y install crypto-policies'
  impact 0.7
  tag check_id: 'C-88009r1188526_chk'
  tag severity: 'high'
  tag gid: 'V-283444'
  tag rid: 'SV-283444r1188528_rule'
  tag stig_id: 'OL08-00-010180'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-87914r1188527_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe package('crypto-policies') do
    it { should be_installed }
  end
end
