control 'SV-248904' do
  title 'OL 8 must not have the "gssproxy" package installed if not required for operational support.'
  desc %q(Verify the operating system is configured to disable nonessential capabilities. The most secure way of ensuring a nonessential capability is disabled is to not have the capability installed. 
 
When an application uses Generic Security Services API (GSSAPI), typically it will have direct access to its security credentials, and all cryptographic operations are performed in the application's process. This is undesirable, but "gssproxy" can help in almost all use cases. It provides privilege separation to applications using the GSSAPI: The gssproxy daemon runs on the system, holds the application's credentials, and performs operations on behalf of the application.)
  desc 'check', 'Note: For Oracle Linux systems, if there is an operational need for gssproxy to be installed, this requirement is Not Applicable.

Determine if the "gssproxy" package is installed with the following command: 
 
$ sudo yum list installed gssproxy 
 
If the "gssproxy" package is installed, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable nonessential capabilities by removing the "gssproxy" package from the system with the following command: 
 
$ sudo yum remove gssproxy'
  impact 0.5
  tag check_id: 'C-52338r1069141_chk'
  tag severity: 'medium'
  tag gid: 'V-248904'
  tag rid: 'SV-248904r1069143_rule'
  tag stig_id: 'OL08-00-040370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52292r1069142_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
