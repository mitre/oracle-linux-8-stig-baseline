control 'SV-248671' do
  title 'OL 8 must enable a user session lock until that user reestablishes access using established identification and authentication procedures for graphical user sessions.'
  desc 'To establish acceptance of the application usage policy, a click-through banner at system logon is required. The system must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', %q(Note: This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify the operating system enables a user's session lock until that user reestablishes access using established identification and authentication procedures with the following command:

$ sudo gsettings get org.gnome.desktop.screensaver lock-enabled

true

If the setting is "false", this is a finding.)
  desc 'fix', %q(Configure OL 8 to enable a user's session lock until that user reestablishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true

Update the system databases:

$ sudo dconf update)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-248671'
  tag rid: 'SV-248671r1015040_rule'
  tag stig_id: 'OL08-00-020030'
  tag fix_id: 'F-52059r779578_fix'
  tag cci: ['CCI-000056', 'CCI-000057', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if package('gnome-desktop3').installed?
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled') do
      its('stdout.strip') { should cmp 'true' }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
