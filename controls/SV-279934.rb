control 'SV-279934' do
  title 'OL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', %q(Verify OL 8 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh

/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/ directory, is missing or is commented out, this is a finding.)
  desc 'fix', 'Configure OL 8 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600'
  impact 0.5
  tag check_id: 'C-84494r1156353_chk'
  tag severity: 'medium'
  tag gid: 'V-279934'
  tag rid: 'SV-279934r1156355_rule'
  tag stig_id: 'OL08-00-020040'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-84399r1156354_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000029-GPOS-00010']
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  system_inactivity_timeout = input('system_inactivity_timeout')

  tmout_lines = command('grep -i tmout /etc/profile /etc/profile.d/*.sh').stdout.strip
  tmout_value = tmout_lines.match(/^[^#]+TMOUT\s*=\s*(\d+)/i)

  describe 'The system' do
    it 'should set a TMOUT value' do
      expect(tmout_value).to_not be_nil, 'No TMOUT value set in /etc/profile or /etc/profile.d/*.sh'
    end
    unless tmout_value.nil?
      it "should exit after #{system_inactivity_timeout} seconds of inactivity" do
        expect(tmout_value.captures.first.to_i).to be <= system_inactivity_timeout
      end
    end
  end
end
