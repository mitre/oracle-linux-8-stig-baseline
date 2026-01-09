control 'SV-248902' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the OL 8 TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  desc 'check', 'Note: If TFTP is not required, it must not be installed. If TFTP is not installed, this rule is not applicable.

Check to see if TFTP server is installed with the following command:

$ sudo dnf list installed | grep tftp-server 
tftp-server.x86_64 x.x-x.el8

Verify the TFTP daemon, if tftp.server is installed, is configured to operate in secure mode with the following command:

$ grep -i execstart /usr/lib/systemd/system/tftp.service
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

Note: The "-s" option ensures the TFTP server only serves files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode with the following command:
$ sudo systemctl edit tftp.service

In the editor, enter:
[Service]
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

After making changes, reload the systemd daemon and restart the TFTP service as follows:
$ sudo systemctl daemon-reload
$ sudo systemctl restart tftp.service'
  impact 0.5
  tag check_id: 'C-52336r1106144_chk'
  tag severity: 'medium'
  tag gid: 'V-248902'
  tag rid: 'SV-248902r1106146_rule'
  tag stig_id: 'OL08-00-040350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52290r1106145_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
