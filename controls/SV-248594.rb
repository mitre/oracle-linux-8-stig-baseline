control 'SV-248594' do
  title 'OL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced, with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of the directories in which they reside. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 is implementing ASLR with the following command:

$ sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2" or is missing, this is a finding.'
  desc 'fix', 'Configure OL 8 to implement ASLR to protect its memory from unauthorized code execution.

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.randomize_va_space = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-248594'
  tag rid: 'SV-248594r1156624_rule'
  tag stig_id: 'OL08-00-010430'
  tag fix_id: 'F-51982r1155452_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end
