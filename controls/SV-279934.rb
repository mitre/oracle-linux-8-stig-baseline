control 'SV-279934' do
  title 'OL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.

'
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

  required_tmout = input('required_tmout')

  tmout_cmd = command('grep -i tmout /etc/profile /etc/profile.d/*.sh')
  tmout_values = tmout_cmd.stdout.lines.filter_map do |line|
    next if line.match?(/:\s*#/) || line.match?(/^\s*#/)

    match = line.match(/\bTMOUT\s*=\s*(\d+)/i)
    match[1].to_i unless match.nil?
  end

  describe 'TMOUT configuration' do
    it "should set TMOUT to #{required_tmout} or less in the grep command output" do
      expect(tmout_values).not_to be_empty,
                                  'No active TMOUT assignment was found in /etc/profile or /etc/profile.d/*.sh'

      expect(tmout_values.all? { |value| value <= required_tmout }).to eq(true),
                                                                       "TMOUT is set higher than #{required_tmout}: #{tmout_cmd.stdout.strip}"
    end
  end
end
