control 'SV-248533' do
  title 'OL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DOD data may be compromised.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements.'
  desc 'check', 'Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-2 approved cryptographic hashing algorithm.

Check the hashing algorithm that is being used to hash passwords with the following command:

$ sudo cat /etc/login.defs | grep -i crypt

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.'
  desc 'fix', 'Configure OL 8 to encrypt all stored passwords.

Edit/modify the following line in the "/etc/login.defs" file and set "[ENCRYPT_METHOD]" to SHA512:

ENCRYPT_METHOD SHA512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-248533'
  tag rid: 'SV-248533r1015028_rule'
  tag stig_id: 'OL08-00-010110'
  tag fix_id: 'F-51921r986325_fix'
  tag cci: ['CCI-000196', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  describe login_defs do
    its('ENCRYPT_METHOD') { should cmp 'SHA512' }
  end
end
