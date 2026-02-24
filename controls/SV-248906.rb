control 'SV-248906' do
  title 'OL 8 must not have the "tuned" package installed if not required for operational support.'
  desc '"Tuned" is a daemon that uses "udev" to monitor connected devices and statically and dynamically tunes system settings according to a selected profile. Disabling the "tuned" package protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Determine if the "tuned" package is installed with the following command:

$ sudo yum list installed tuned

If the "tuned" package is installed, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable non-essential capabilities by removing the "tuned" package from the system with the following command:

$ sudo yum remove tuned'
  impact 0.5
  tag check_id: 'C-52340r780282_chk'
  tag severity: 'medium'
  tag gid: 'V-248906'
  tag rid: 'SV-248906r991589_rule'
  tag stig_id: 'OL08-00-040390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52294r780283_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('tuned_required')
    describe package('tuned') do
      it { should be_installed }
    end
  else
    describe package('tuned') do
      it { should_not be_installed }
    end
  end
end
