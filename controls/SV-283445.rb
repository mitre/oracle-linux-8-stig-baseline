control 'SV-283445' do
  title 'OL 8 must implement a FIPS 140-3-compliant systemwide cryptographic policy.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Using weak or untested encryption algorithms undermines the purposes of using encryption to protect data.

'
  desc 'check', %q(Verify OL 8 is set to use a FIPS 140-3-compliant systemwide cryptographic policy with the following command:

$ update-crypto-policies --show

FIPS

If the systemwide crypto policy is not set to "FIPS", this is a finding.

Note: If subpolicies have been configured, they could be listed in a colon-separated list starting with "FIPS" as follows FIPS:<SUBPOLICY-NAME>. This is not a finding.

Note: Subpolicies like AD-SUPPORT must be configured according to the latest guidance from the operating system vendor.

Verify the current minimum crypto-policy configuration with the following commands:

$ grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol

hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256
min_rsa_size = 2048

If the "hash" values do not include at least the following FIPS 140-3-compliant algorithms "SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256", this is a finding.

If there are algorithms that include "SHA1" or a hash value less than "224" this is a finding.

If the "min_rsa_size" is not set to a value of at least "2048", this is a finding.

If these commands do not return any output, this is a finding.)
  desc 'fix', 'Configure OL 8 to use a FIPS 140-3-compliant systemwide cryptographic policy.

Create a subpolicy for enhancements to the base systemwide crypto-policy by creating the file /etc/crypto-policies/policies/modules/STIG.pmod with the following content:

# Define ciphers and MACs for OpenSSH and libssh
cipher@SSH=AES-256-GCM AES-256-CTR AES-128-GCM AES-128-CTR
mac@SSH=HMAC-SHA2-512 HMAC-SHA2-256

Apply the policy enhancements to the FIPS systemwide cryptographic policy level with the following command:

$ sudo update-crypto-policies --set FIPS:STIG

Note: If additional subpolicies are being employed, they must be added to the update-crypto-policies command.

To make the cryptographic settings effective for already running services and applications, restart the system:

$ sudo reboot'
  impact 0.7
  tag check_id: 'C-88010r1188411_chk'
  tag severity: 'high'
  tag gid: 'V-283445'
  tag rid: 'SV-283445r1188529_rule'
  tag stig_id: 'OL08-00-010181'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-87915r1188412_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  weak_hashes = %w(SHA1 MD5)
  required_hashes = %w(SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256)
  min_rsa_size = 2048

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    # Policy must be FIPS, optionally with a colon-separated subpolicy (e.g. FIPS:OSPP)
    describe command('update-crypto-policies --show').stdout.strip do
      it { should match(/^FIPS(:\S+)?$/) }
    end

    current_pol = command('grep -E "rsa_size|hash" /etc/crypto-policies/state/CURRENT.pol').stdout

    describe 'FIPS crypto policy hash algorithms' do
      # compare configured hashes against the required/weak lists
      it 'should include all required FIPS 140-3-compliant hash algorithms' do
        hash_line = current_pol[/^hash\s*=\s*(.*)$/, 1].to_s
        configured_hashes = hash_line.split
        missing = required_hashes - configured_hashes
        expect(missing).to be_empty, "Missing required hash algorithms: #{missing.join(', ')}"
      end

      it 'should not include weak hash algorithms' do
        hash_line = current_pol[/^hash\s*=\s*(.*)$/, 1].to_s
        configured_hashes = hash_line.split
        present_weak = configured_hashes & weak_hashes
        expect(present_weak).to be_empty, "Weak hash algorithms present: #{present_weak.join(', ')}"
      end
    end

    describe 'FIPS crypto policy min_rsa_size' do
      it "should be at least #{min_rsa_size}" do
        # nil-safe: to_i on a failed match (nil) evaluates to 0, correctly failing the check
        rsa_line = current_pol[/^min_rsa_size\s*=\s*(\d+)/, 1]
        expect(rsa_line.to_i).to be >= min_rsa_size
      end
    end
  end
end
