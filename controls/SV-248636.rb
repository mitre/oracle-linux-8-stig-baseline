control 'SV-248636' do
  title 'All OL 8 world-writable directories must be owned by root, sys, bin, or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an application User Identifier (UID), unauthorized users may be able to modify files created by others.

The only authorized public directories are the temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a UID lower than 1000. Run it once for each local partition [PART]:

$ sudo find [PART] -xdev -type d -perm -0002 -uid +999 -print

If there is output, this is a finding.'
  desc 'fix', 'Investigate any world-writable directories that are not owned by a system account and then delete the files or assign them to an appropriate group.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248636'
  tag rid: 'SV-248636r991589_rule'
  tag stig_id: 'OL08-00-010700'
  tag fix_id: 'F-52024r779473_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else

    partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq

    cmd = "find #{partitions.join(' ')} -xdev -type d -perm -0002 -uid +999 -print"
    failing_dirs = command(cmd).stdout.split("\n").uniq

    describe 'Any world-writeable directories' do
      it 'should be owned by system accounts' do
        expect(failing_dirs).to be_empty, "Failing directories:\n\t- #{failing_dirs.join("\n\t- ")}"
      end
    end
  end
end
