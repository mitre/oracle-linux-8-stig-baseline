control 'SV-248827' do
  title 'OL 8 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository.'
  desc 'The EPEL is a repository of high-quality open-source packages for enterprise-class Linux distributions such as RHEL, CentOS, AlmaLinux, Rocky Linux, and Oracle Linux. These packages are not part of the official distribution but are built using the same Fedora build system to ensure compatibility and maintain quality standards.'
  desc 'check', 'Verify that OL 8 is not able to install packages from the EPEL with the following command:

$ dnf repolist
repo id                         repo name
ol8_UEKR7                       Latest Unbreakable Enterprise Kernel Release 7 for Oracle Linux 8 (x86_64)
ol8_appstream                   Oracle Linux 8 Application Stream (x86_64)
ol8_baseos_latest               Oracle Linux 8 BaseOS Latest (x86_64)

If any repositories containing the word "epel" in the name exist, this is a finding.'
  desc 'fix', 'The repo package can be manually removed with the following command:

$ sudo dnf remove epel-release

Configure OL 8 to disable use of the EPEL repository with the following command:

$ sudo dnf config-manager --set-disabled epel'
  impact 0.7
  tag check_id: 'C-52261r1134848_chk'
  tag severity: 'high'
  tag gid: 'V-248827'
  tag rid: 'SV-248827r1134850_rule'
  tag stig_id: 'OL08-00-040010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-52215r1134849_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  repo_ids = command('dnf repolist all 2>/dev/null').stdout.lines.map { |line| line.split.first.to_s.strip }
  puts repo_ids
  epel_repo_ids = repo_ids.grep(/^epel/i)

  describe 'Configured package repositories' do
    it 'must not include EPEL repositories' do
      expect(epel_repo_ids).to be_empty, "EPEL repositories found: #{epel_repo_ids.join(', ')}"
    end
  end

  describe package('epel-release') do
    it { should_not be_installed }
  end
end
