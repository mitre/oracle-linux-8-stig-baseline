control 'SV-283458' do
  title 'The OL 8 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

OL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', %q(Verify the OL 8 SSH server is configured to use only ciphers employing FIPS 140-3-approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ sudo grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config
CRYPTO_POLICY='-oCiphers=aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "opensshserver.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.)
  desc 'fix', 'Configure the OL 8 SSH server to use only ciphers employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-88023r1188516_chk'
  tag severity: 'high'
  tag gid: 'V-283458'
  tag rid: 'SV-283458r1188518_rule'
  tag stig_id: 'OL08-00-010291'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-87928r1188517_fix'
  tag 'documentable'
  tag cci: ['CCI-000877', 'CCI-001453']
  tag nist: ['MA-4 c', 'AC-17 (2)']
end
