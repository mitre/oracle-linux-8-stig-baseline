control 'SV-248653' do
  title 'OL 8 systems, versions 8.2 and above, must automatically lock an account when three unsuccessful logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.

In OL 8.2, the "/etc/security/faillock.conf" file was incorporated to centralize the configuration of the "pam_faillock.so" module. Also introduced is a "local_users_only" option that will only track failed user authentication attempts for local users in "/etc/passwd" and ignore centralized (AD, IdM, LDAP, etc.) users to allow the centralized platform to solely manage user lockout.

From "faillock.conf" man pages: Note that the default directory that "pam_faillock" uses is usually cleared on system boot so the access will be reenabled after system reboot. If that is undesirable, a different tally directory must be set with the "dir" option.'
  desc 'check', %q(Note: This check applies to OL versions 8.2 or newer. If the system is OL version 8.0 or 8.1, this check is not applicable.

Verify the "/etc/security/faillock.conf" file is configured to lock an account after three unsuccessful logon attempts:

$ sudo grep 'deny =' /etc/security/faillock.conf

deny = 3

If the "deny" option is not set to "3" or less (but not "0") or is missing or commented out, this is a finding.)
  desc 'fix', 'Configure OL 8 to lock an account when three unsuccessful logon attempts occur.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

deny = 3'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-248653'
  tag rid: 'SV-248653r958388_rule'
  tag stig_id: 'OL08-00-020011'
  tag fix_id: 'F-52041r779524_fix'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  unsuccessful_attempts = input('unsuccessful_attempts')
  pam_auth_files = input('pam_auth_files')

  only_if('This system uses Centralized Account Management to manage this requirement', impact: 0.0) {
    !input('central_account_management')
  }

  message = <<~MESSAGE
    \n\nThis check only applies to OL versions 8.0 or 8.1.\n
    The system is running OL version: #{os.version}, this requirement is Not Applicable.
  MESSAGE
  if os.version.minor >= 2
    impact 0.0
    describe 'This requirement only applies to OL 8 version(s) 8.0 and 8.1' do
      skip message
    end
  else
    [
      pam_auth_files['password-auth'],
      pam_auth_files['system-auth']
    ].each do |path|
      describe pam(path) do
        its('lines') {
          should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_integer_arg('deny',
                                                                                                            '<=', unsuccessful_attempts)
        }
        its('lines') {
          should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_integer_arg('deny',
                                                                                                            '>=', 0)
        }
      end
    end
  end
end
