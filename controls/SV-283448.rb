control 'SV-283448' do
  title 'The OL 8 SSH client must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash. 

OL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
  desc 'check', 'Verify the SSH client is configured to use only ciphers employing FIPS 140-3-approved algorithms.

Verify the ciphers in the systemwide SSH configuration file using the following command:

$ grep -i Ciphers /etc/crypto-policies/back-ends/openssh.config 

Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "openssh.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the SSH client to use only ciphers employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. Restart the system for the changes to take place.'
  impact 0.7
  tag check_id: 'C-88013r1188534_chk'
  tag severity: 'high'
  tag gid: 'V-283448'
  tag rid: 'SV-283448r1188536_rule'
  tag stig_id: 'OL08-00-010184'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-87918r1188535_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  approved_ciphers = input('openssh_client_required_ciphers')

  # the crypto-policies backend file uses "Ciphers" (no -o prefix), unlike opensshserver.config
  openssh_conf = ssh_config('/etc/crypto-policies/back-ends/openssh.config')

  describe 'SSH client ciphers in /etc/crypto-policies/back-ends/openssh.config' do
    it 'should only contain FIPS 140-3-approved ciphers' do
      configured_ciphers = openssh_conf.ciphers
      expect(configured_ciphers).not_to be_nil, 'Ciphers entry is missing or commented out'
      expect(configured_ciphers.split(',').sort).to eq(approved_ciphers.sort)
    end
  end
end
