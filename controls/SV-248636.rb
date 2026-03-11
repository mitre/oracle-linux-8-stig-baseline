control 'SV-248636' do
  title 'All OL 8 world-writable directories must be owned by root, sys, bin, or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an application User Identifier (UID), unauthorized users may be able to modify files created by others.

The only authorized public directories are the temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Verify OL 8 world writable directories are owned by root, a system account, or an application account with the following command:

$ sudo find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \\; 2>/dev/null

If there is output that indicates world-writable directories are owned by any account other than root or an approved system account, this is a finding.'
  desc 'fix', 'Configure all OL 8 public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Use the following command template to set ownership of public directories to root or a system account:

$ sudo chown [root or system account] [Public Directory]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-248636'
  tag rid: 'SV-248636r1156655_rule'
  tag stig_id: 'OL08-00-010700'
  tag fix_id: 'F-52024r1155521_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else
    cmd = 'find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \; 2>/dev/null'
    failing_dirs = command(cmd).stdout.split("\n").reject(&:empty?).uniq

    describe 'World-writable directories owned by non-system accounts' do
      it 'should not exist' do
        expect(failing_dirs).to be_empty, "Failing directories:\n\t- #{failing_dirs.join("\n\t- ")}"
      end
    end
  end
end
