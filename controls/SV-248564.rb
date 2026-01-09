control 'SV-248564' do
  title 'The OL 8 operating system must implement DOD-approved encryption in the OpenSSL package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

OL 8 incorporates systemwide crypto policies by default. The employed algorithms can be viewed in the "/etc/crypto-policies/back-ends/openssl.config" file.'
  desc 'check', 'Verify that OL 8 is in FIPS mode with the following command:

$ sudo fips-mode-setup --check
FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.

If any other lines are returned by the above command, run the following command to view the currently applied crypto-policy:

$ update-crypto-policies --show
FIPS

If the policy is not "FIPS" or a FIPS policy authorized by and documented with the ISSO, this is a finding.'
  desc 'fix', 'Configure the OL 8 OpenSSL library to use only ciphers employing FIPS 140-2/140-3 approved algorithms with the following command:

$ sudo fips-mode-setup --enable

A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-248564'
  tag rid: 'SV-248564r1134844_rule'
  tag stig_id: 'OL08-00-010293'
  tag fix_id: 'F-51952r1134843_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if("Checking the host's FIPS compliance can't be done within the container and should be reveiwed manually.") {
    !(virtualization.system.eql?('docker') && !file('/etc/pki/tls/openssl.cnf').exist?)
  }

  describe 'A line in the OpenSSL config file' do
    subject { command('grep -i opensslcnf.config /etc/pki/tls/openssl.cnf').stdout.strip }
    it { should match(/^\.include.*opensslcnf.config$/) }
  end

  describe 'System-wide crypto policy' do
    subject { command('update-crypto-policies --show').stdout.strip }
    it { should eq input('system_wide_crypto_policy') }
  end
end
