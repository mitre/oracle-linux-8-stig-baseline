control 'SV-248593' do
  title 'OL 8 must not let Meltdown and Spectre exploit critical vulnerabilities in modern processors.'
  desc 'Hardware vulnerabilities allow programs to steal data that is currently processed on the computer. While programs are typically not permitted to read data from other programs, a malicious program can exploit Meltdown and Spectre to obtain secrets stored in the memory of other running programs. This might include passwords stored in a password manager or browser; personal photos, emails, and instant messages; and business-critical documents.'
  desc 'check', 'Verify OL 8 is configured to enable mitigations with the following command:

$ grubby --info=/boot/vmlinuz-$(uname -r) | grep mitigations

If the "mitigations" parameter is set to "off" (mitigations=off), this is a finding.

Note: The default behavior of the kernel is to enable mitigations for vulnerabilities like Meltdown and Spectre based on hardware and system requirements. Therefore, if the "mitigation" parameter is not present or if it is set to on this is not a finding.'
  desc 'fix', 'Determine the default kernel:  
 
$ sudo grubby --default-kernel 
 
/boot/vmlinuz-5.4.17-2011.1.2.el8uek.x86_64 

Using the default kernel, remove the argument that sets the Meltdown mitigations to "off": 
 
$ sudo grubby --update-kernel=<path-to-default-kernel>  --remove-args=mitigations=off 
 
Reboot the system for the change to take effect.'
  impact 0.5
  tag check_id: 'C-52027r1069158_chk'
  tag severity: 'medium'
  tag gid: 'V-248593'
  tag rid: 'SV-248593r1069159_rule'
  tag stig_id: 'OL08-00-010424'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51981r951561_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
