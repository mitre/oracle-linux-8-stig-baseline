control 'SV-283447' do
  title 'OL 8 cryptographic policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Using weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

'
  desc 'check', 'Verify OL 8 cryptographic policies are not overridden.

Verify the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --is-applied

The configured policy is applied

If the returned message does not match the above, this is a finding.'
  desc 'fix', 'Configure OL 8 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. Restart the system for the changs to take place.'
  impact 0.7
  tag check_id: 'C-88012r1188531_chk'
  tag severity: 'high'
  tag gid: 'V-283447'
  tag rid: 'SV-283447r1188533_rule'
  tag stig_id: 'OL08-00-010183'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-87917r1188532_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
end
