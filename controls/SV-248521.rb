control 'SV-248521' do
  title 'OL 8 must be a vendor-supported release.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across the DOD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

End Of Life dates for Oracle Linux 8 releases are as follows:
Current end of Premier Support for Oracle Linux 8 is July 2029.
Current end of Extended Support for Oracle Linux 8 is July 2032.

Each minor version reaches end of life when the new version is released.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

$ sudo cat /etc/oracle-release
Oracle Linux Server release 8.10

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248521'
  tag rid: 'SV-248521r1156679_rule'
  tag stig_id: 'OL08-00-010000'
  tag fix_id: 'F-51909r779128_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  release = os.release

  EOMS_DATE = {
    /^8\.1$/ => '30 November 2021',
    /^8\.2$/ => '30 April 2022',
    /^8\.3$/ => '30 April 2021',
    /^8\.4$/ => '31 May 2023',
    /^8\.5$/ => '31 May 2022',
    /^8\.6$/ => '31 May 2024',
    /^8\.7$/ => '31 May 2023',
    /^8\.8$/ => '31 May 2025',
    /^8\.9$/ => '31 May 2024',
    /^8\.10$/ => '31 May 2029'
  }.find { |k, _v| k.match(release) }&.last

  describe "The release \"#{release}\" is still be within the support window" do
    it "ending on #{EOMS_DATE}" do
      expect(Date.today).to be <= Date.parse(EOMS_DATE)
    end
  end
end
