control 'SV-248689' do
  title 'OL 8 must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

OL 8 uses "pwquality" as a mechanism to enforce password complexity. Note that in order to require numeric characters without degrading the minlen value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".'
  desc 'check', 'Verify the value for "dcredit" in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command:

$ sudo grep -r dcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dcredit = -1

If the value of "dcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory:

dcredit = -1

Remove any configurations that conflict with the above value.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag gid: 'V-248689'
  tag rid: 'SV-248689r1015049_rule'
  tag stig_id: 'OL08-00-020130'
  tag fix_id: 'F-52077r858634_fix'
  tag cci: ['CCI-000194', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'dcredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `dcredit` set' do
      expect(value).not_to be_empty, 'dcredit is not set in pwquality.conf'
    end

    it 'only sets `dcredit` once' do
      expect(value.length).to eq(1), 'dcredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `dcredit` to a positive value' do
      expect(value.first.to_i).to be < 0, 'dcredit is not set to a negative value in pwquality.conf'
    end
  end
end
