control 'SV-283451' do
  title 'OL 8 must implement DOD-approved encryption in the bind package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

OL 8 incorporates systemwide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.

'
  desc 'check', %q(Verify BIND uses the system crypto policy with the following command:

Note: If the "bind" package is not installed, this is not applicable.

$ sudo grep include /etc/named.conf

include "/etc/crypto-policies/back-ends/bind.config";'

If BIND is installed and the BIND config file does not include "/etc/crypto-policies/back-ends/bind.config" directive or the line is commented out, this is a finding.)
  desc 'fix', 'Configure BIND to use the system crypto policy.

Add the following line to the "options" section in "/etc/named.conf":

include "/etc/crypto-policies/back-ends/bind.config";'
  impact 0.7
  tag check_id: 'C-88016r1188542_chk'
  tag severity: 'high'
  tag gid: 'V-283451'
  tag rid: 'SV-283451r1188543_rule'
  tag stig_id: 'OL08-00-010187'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-87921r1188430_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)']
end
