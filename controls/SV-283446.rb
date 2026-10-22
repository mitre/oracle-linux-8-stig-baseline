control 'SV-283446' do
  title 'OL 8 must implement NIST FIPS-validated cryptography for the following: To provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Using weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

OL 8 utilizes GRUB 2 as the default bootloader. Note that GRUB 2 command-line parameters are defined in the "kernelopts" variable of the /boot/grub2/grubenv file for all kernel boot entries. The command "fips-mode-setup" modifies the "kernelopts" variable, which in turn updates all kernel boot entries.

The fips=1 kernel option must be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users must also ensure the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a nonunique key.'
  desc 'check', %q(Verify OL 8 is set to use a DoW-approved FIPS 140-3-compliant systemwide cryptographic policy.

Verify the current systemwide crypto-policy with the following command:

$ update-crypto-policies --show
FIPS

If the systemwide crypto-policy is not set to "FIPS", this is a finding.

Verify the current minimum crypto-policy configuration with the following commands:

$ sudo grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol
hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512
min_rsa_size = 2048

If the "hash" values do not include at least the following FIPS 140-3-compliant algorithms, this is a finding:

"SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512"

If any algorithms include "SHA1" or a hash value less than "224", this is a finding.

If the "min_rsa_size" is not set to a value of at least "2048", this is a finding.

If these commands do not return any output, this is a finding.)
  desc 'fix', 'Configure OL 8 to use a DoW-approved FIPS 140-3-compliant systemwide cryptographic policy.

Set the systemwide crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS
Setting system policy to FIPS

Note: Systemwide crypto-policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-88011r1262450_chk'
  tag severity: 'high'
  tag gid: 'V-283446'
  tag rid: 'SV-283446r1262452_rule'
  tag stig_id: 'OL08-00-010182'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-87916r1262451_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'SC-8', 'SC-13 b']

  allowed_subpolicies = %w[AD-SUPPORT NO-ENFORCE-EMS]
  # profile consumer must explicitly list any subpolicy they've cleared with the ISSO
  authorized_subpolicies = input('fips_authorized_subpolicies')

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
    policy = command('update-crypto-policies --show').stdout.strip
    # "FIPS:SUBPOLICY" splits into main policy and optional subpolicy name
    main_policy, subpolicy = policy.split(':', 2)

    describe 'Systemwide crypto policy name' do
      it 'should be FIPS' do
        expect(main_policy).to cmp 'FIPS'
      end
    end

    if subpolicy
      describe "FIPS subpolicy module #{subpolicy}" do
        # any subpolicy other than these two is a finding regardless of authorization
        it 'must be one of the recognized modules (AD-SUPPORT, NO-ENFORCE-EMS)' do
          expect(allowed_subpolicies).to include(subpolicy), "Unrecognized subpolicy module: #{subpolicy}"
        end

        # even a recognized subpolicy is a finding unless the ISSO has signed off via the input
        it 'must be documented as an operational requirement with the ISSO' do
          expect(authorized_subpolicies).to include(subpolicy), "Subpolicy #{subpolicy} is not listed in the 'fips_authorized_subpolicies' input as ISSO-authorized"
        end
      end
    end
  end
end
