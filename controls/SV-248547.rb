control 'SV-248547' do
  title 'The krb5-server package must not be installed on OL 8.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

OL 8 systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

Currently, Kerberos does not use FIPS 140-2 cryptography.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify the krb5-server package has not been installed on the system with the following commands:

If the system is a workstation or is using krb5-server-1.17-18.el8.x86_64 or newer, this is Not Applicable

$ sudo yum list installed krb5-server

krb5-server.x86_64 1.17-9.el8 repository

If the krb5-server package is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the krb5-server package with the ISSO as an operational
requirement or remove it from the system with the following command:

    $ sudo yum remove krb5-server'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-248547'
  tag rid: 'SV-248547r971535_rule'
  tag stig_id: 'OL08-00-010163'
  tag fix_id: 'F-51935r779206_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
  tag 'host'
  tag 'container'

  kerb = package('krb5-server')

  if (kerb.installed? && kerb.version >= '1.17-9.el8') || input('system_is_workstation')
    impact 0.0
    describe 'N/A' do
      skip 'The system is a workstation or is utilizing krb5-server-1.17-9.el8 or newer; control is Not Applicable.'
    end
  elsif input('kerberos_required')
    describe package('krb5-server') do
      it { should be_installed }
    end
  else
    describe package('krb5-server') do
      it { should_not be_installed }
    end
  end
end
