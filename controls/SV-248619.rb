control 'SV-248619' do
  title 'OL 8 must prevent special devices on nonroot local partitions.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access. The only legitimate location for device files is the /dev directory located on the root partition.'
  desc 'check', %q(Note: This control is not applicable to vfat file systems.

Verify all nonroot local partitions are mounted with the "nodev" option with the following command:

$ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

If any output is produced, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on all nonroot local partitions.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248619'
  tag rid: 'SV-248619r1156678_rule'
  tag stig_id: 'OL08-00-010580'
  tag fix_id: 'F-52007r1156677_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'nodev'

  mount_stdout = command('mount').stdout.lines
  failing_mount_points = mount_stdout.select { |mp| mp.match(%r{^/dev\S*\s+on\s+/\S}) }.reject { |mp| mp.match(/\(.*#{option}.*\)/) }

  describe "All mounted devices outside of '/dev' directory" do
    it "should be mounted with the '#{option}' option" do
      expect(failing_mount_points).to be_empty, "Failing devices:\n\t- #{failing_mount_points.join("\n\t- ")}"
    end
  end
end
