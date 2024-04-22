cisecurity = node['cis_compliance']['xccdf_org']['cisecurity']

file 'sshd.changed' do
  action :nothing
  path '/tmp/.sshd-changed'
  mode 0600
  owner 'root'
  group 'root'
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.7_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less

replace_or_add 'SSH MaxAuthTries' do
  path '/etc/ssh/sshd_config'
  pattern 'MaxAuthTries.*'
  line 'MaxAuthTries 4'
  notifies :create, 'file[sshd.changed]', :immediately
  only_if { cisecurity['benchmarks_rule_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.12_Ensure_SSH_PermitUserEnvironment_is_disabled

append_if_no_line "Ensure sudo commands use pty" do
  path "/etc/ssh/sshd_config"
  line "PermitUserEnvironment no"
  only_if { cisecurity['benchmarks_rule_Ensure_SSH_PermitUserEnvironment_is_disabled'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.14_Ensure_only_strong_MAC_algorithms_are_used

replace_or_add 'Macs' do
  path '/etc/ssh/sshd_config'
  pattern 'Macs.*'
  line 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'
  only_if { cisecurity['benchmarks_rule_Ensure_only_strong_MAC_algorithms_are_used'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.17_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less

replace_or_add 'SSH LoginGraceTime' do
  path '/etc/ssh/sshd_config'
  pattern 'LoginGraceTime.*'
  line 'LoginGraceTime 60'
  only_if { cisecurity['benchmarks_rule_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.18_Ensure_SSH_warning_banner_is_configured

replace_or_add 'Set SSH Banner' do
  path '/etc/ssh/sshd_config'
  pattern 'Banner.*'
  line 'Banner /etc/ssh/sshd-banner'
  notifies :create, 'file[sshd.changed]', :immediately
  only_if { cisecurity['benchmarks_rule_Ensure_SSH_warning_banner_is_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.3.21_Ensure_SSH_MaxStartups_is_configured

replace_or_add 'SSH LoginGraceTime' do
  path '/etc/ssh/sshd_config'
  pattern 'MaxStartups.*'
  line 'MaxStartups 10:30:60'
  only_if { cisecurity['benchmarks_rule_Ensure_SSH_MaxStartups_is_configured'] }
end
