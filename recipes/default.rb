#
# Cookbook:: cis-hardening
# Recipe:: default
#
# Copyright:: 2023, NewCold customer team at Schuberg Philis, All Rights Reserved.
sysctl_items = {}
cisecurity = node['cis_compliance']['xccdf_org']['cisecurity']

directory '/var/log/journal' do
  owner 'root'
  group 'root'
  mode '0750'
  action :create
end

include_recipe 'os-hardening::auditd'
include_recipe 'os-hardening::limits'
# include_recipe 'os-hardening::login_defs'
include_recipe 'os-hardening::minimize_access'
include_recipe 'os-hardening::packages'
# include_recipe 'os-hardening::pam'
include_recipe 'os-hardening::profile'
include_recipe 'os-hardening::securetty'
include_recipe 'os-hardening::selinux'
include_recipe 'os-hardening::suid_sgid'

# xccdf_org.cisecurity.benchmarks_rule_1.1.3, 1.1.4, 1.1.5, 1.1.7, 1.1.8, 1.1.9, 1.1.12, 1.1.13, 1.1.14
include_recipe "#{cookbook_name}::fstab"

# xccdf_org.cisecurity.benchmarks_rule_1.1.23_Disable_USB_Storage
%w(uas usb-storage).each do |m|
  kernel_module m do
    action [ :unload, :disable, :blacklist ]
    only_if { cisecurity['benchmarks_rule_1.1.23_Disable_USB_Storage'] }
  end
end

# xccdf_org.cisecurity.benchmarks_rule_1.3.2_Ensure_sudo_commands_use_pty
file '/etc/sudoers.d/CIS_1.3.2' do
  owner 'root'
  group 'root'
  mode '0440'
  content "Defaults use_pty\n"
  only_if { cisecurity['benchmarks_rule_Ensure_sudo_commands_use_pty'] }
end

# xccdf_org.cisecurity.benchmarks_rule_1.3.3_Ensure_sudo_log_file_exists
file '/etc/sudoers.d/CIS_1.3.3' do
  owner 'root'
  group 'root'
  mode '0440'
  content "Defaults logfile=\"/var/log/sudo.log\"\n"
  only_if { cisecurity['benchmarks_rule_Ensure_sudo_log_file_exists'] }
end

# xccdf_org.cisecurity.benchmarks_rule_1.6.1_Ensure_core_dumps_are_restricted
sysctl_items['fs.suid_dumpable'] = 0 if cisecurity['benchmarks_rule_Ensure_core_dumps_are_restricted']

# file '/etc/security/limits.d/CIS.conf' do
#   owner 'root'
#   group 'root'
#   mode '0644'
#   content "* hard core 0\n"
#   only_if { cisecurity['benchmarks_rule_Ensure_core_dumps_are_restricted'] }
# end

# xccdf_org.cisecurity.benchmarks_rule_1.6.2_Ensure_address_space_layout_randomization_ASLR_is_enabled
sysctl_items['kernel.randomize_va_space'] = 2 if cisecurity['benchmarks_rule_Ensure_address_space_layout_randomization_ASLR_is_enabled']

# xccdf_org.cisecurity.benchmarks_rule_1.8.1.1_Ensure_message_of_the_day_is_configured_properly
# xccdf_org.cisecurity.benchmarks_rule_1.7.2_Ensure_local_login_warning_banner_is_configured_properly
# xccdf_org.cisecurity.benchmarks_rule_1.7.3_Ensure_remote_login_warning_banner_is_configured_properly
['/etc/issue', '/etc/issue.net'].each do |loginfile|
  file loginfile do
    content "This system is restricted to authorized users only. Individuals attempting unauthorized access will be prosecuted.\n" \
            "If unauthorized, terminate access now! Continued access indicates your acceptance of this information.\n"
    mode 0644
    owner 'root'
    group 'root'
    only_if { cisecurity['benchmarks_rule_Ensure_message_of_the_day_is_configured_properly'] }
    action :create
  end
end

# # xccdf_org.cisecurity.benchmarks_rule_1.10_Ensure_system-wide_crypto_policy_is_not_legacy
# bash 'crypto-policies' do
#   code <<-EOH
#   sed -i 's/^LEGACY/DEFAULT/' /etc/crypto-policies/config
#   EOH
#   only_if { cisecurity['benchmarks_rule_Ensure_system-wide_crypto_policy_is_not_legacy'] }
#   only_if { node['platform_version'].to_i >= 8 }
#   action :run
# end

# xccdf_org.cisecurity.benchmarks_rule_2.3.2_Ensure_telnet_client_is_not_installed
package 'telnet' do
  action :remove
  only_if { cisecurity['benchmarks_rule_Ensure_telnet_client_is_not_installed'] }
end

# xccdf_org.cisecurity.benchmarks_rule_3.1.1_Ensure_IP_forwarding_is_disabled
sysctl_items['net.ipv4.ip_forward'] = 0 if cisecurity['benchmarks_rule_Ensure_IP_forwarding_is_disabled']
sysctl_items['net.ipv6.conf.all.forwarding'] = 0 if cisecurity['benchmarks_rule_Ensure_IP_forwarding_is_disabled']

# xccdf_org.cisecurity.benchmarks_rule_3.1.2_Ensure_packet_redirect_sending_is_disabled
sysctl_items['net.ipv4.conf.all.send_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_packet_redirect_sending_is_disabled']
sysctl_items['net.ipv4.conf.default.send_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_packet_redirect_sending_is_disabled']

# xccdf_org.cisecurity.benchmarks_rule_3.2.1_Ensure_source_routed_packets_are_not_accepted
sysctl_items['net.ipv4.conf.all.accept_source_route'] = 0 if cisecurity['benchmarks_rule_Ensure_source_routed_packets_are_not_accepted']
sysctl_items['net.ipv4.conf.default.accept_source_route'] = 0 if cisecurity['benchmarks_rule_Ensure_source_routed_packets_are_not_accepted']
sysctl_items['net.ipv6.conf.all.accept_source_route'] = 0 if cisecurity['benchmarks_rule_Ensure_source_routed_packets_are_not_accepted']
sysctl_items['net.ipv6.conf.default.accept_source_route'] = 0 if cisecurity['benchmarks_rule_Ensure_source_routed_packets_are_not_accepted']

# xccdf_org.cisecurity.benchmarks_rule_3.2.2_Ensure_ICMP_redirects_are_not_accepted
sysctl_items['net.ipv4.conf.all.accept_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_ICMP_redirects_are_not_accepted']
sysctl_items['net.ipv4.conf.default.accept_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_ICMP_redirects_are_not_accepted']
sysctl_items['net.ipv6.conf.all.accept_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_ICMP_redirects_are_not_accepted']
sysctl_items['net.ipv6.conf.default.accept_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_ICMP_redirects_are_not_accepted']

# xccdf_org.cisecurity.benchmarks_rule_3.2.3_Ensure_secure_ICMP_redirects_are_not_accepted
sysctl_items['net.ipv4.conf.all.secure_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_secure_ICMP_redirects_are_not_accepted']
sysctl_items['net.ipv4.conf.default.secure_redirects'] = 0 if cisecurity['benchmarks_rule_Ensure_secure_ICMP_redirects_are_not_accepted']

# xccdf_org.cisecurity.benchmarks_rule_3.2.4_Ensure_suspicious_packets_are_logged
sysctl_items['net.ipv4.conf.all.log_martians'] = 1 if cisecurity['benchmarks_rule_Ensure_suspicious_packets_are_logged']
sysctl_items['net.ipv4.conf.default.log_martians'] = 1 if cisecurity['benchmarks_rule_Ensure_suspicious_packets_are_logged']

# xccdf_org.cisecurity.benchmarks_rule_3.2.5_Ensure_broadcast_ICMP_requests_are_ignored
sysctl_items['net.ipv4.icmp_echo_ignore_broadcasts'] = 1 if cisecurity['benchmarks_rule_Ensure_broadcast_ICMP_requests_are_ignored']

# xccdf_org.cisecurity.benchmarks_rule_3.2.6_Ensure_bogus_ICMP_responses_are_ignored
sysctl_items['net.ipv4.icmp_ignore_bogus_error_responses'] = 1 if cisecurity['benchmarks_rule_Ensure_bogus_ICMP_responses_are_ignored']

# xccdf_org.cisecurity.benchmarks_rule_3.2.7_Ensure_Reverse_Path_Filtering_is_enabled
sysctl_items['net.ipv4.conf.all.rp_filter'] = 1 if cisecurity['benchmarks_rule_Ensure_Reverse_Path_Filtering_is_enabled']
sysctl_items['net.ipv4.conf.default.rp_filter '] = 1 if cisecurity['benchmarks_rule_Ensure_Reverse_Path_Filtering_is_enabled']

# xccdf_org.cisecurity.benchmarks_rule_3.2.8_Ensure_TCP_SYN_Cookies_is_enabled
sysctl_items['net.ipv4.tcp_syncookies'] = 1 if cisecurity['benchmarks_rule_Ensure_TCP_SYN_Cookies_is_enabled']

# xccdf_org.cisecurity.benchmarks_rule_3.2.9_Ensure_IPv6_router_advertisements_are_not_accepted
sysctl_items['net.ipv6.conf.all.accept_ra'] = 0 if cisecurity['benchmarks_rule_Ensure_IPv6_router_advertisements_are_not_accepted']
sysctl_items['net.ipv6.conf.default.accept_ra'] = 0 if cisecurity['benchmarks_rule_Ensure_IPv6_router_advertisements_are_not_accepted']

# xccdf_org.cisecurity.benchmarks_rule_3.5_Ensure_wireless_interfaces_are_disabled
bash 'disable_wifi' do
  code <<-EOH
  nmcli radio wifi off
  EOH
  only_if { cisecurity['benchmarks_rule_Ensure_wireless_interfaces_are_disabled'] }
  only_if { node['platform_version'].to_i >= 8 }
  not_if 'nmcli radio wifi | grep disabled'
  ignore_failure true
  action :run
end

bash 'disable_wwan' do
  code <<-EOH
  nmcli radio wwan off
  EOH
  only_if { cisecurity['benchmarks_rule_Ensure_wireless_interfaces_are_disabled'] }
  only_if { node['platform_version'].to_i >= 8 }
  not_if 'nmcli radio wwan | grep disabled'
  ignore_failure true
  action :run
end

journald_conf = ['[Journal]']

# xccdf_org.cisecurity.benchmarks_rule_4.2.2.1_Ensure_journald_is_configured_to_send_logs_to_rsyslog
journald_conf.push('ForwardToSyslog=yes') if cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_send_logs_to_rsyslog']

# xccdf_org.cisecurity.benchmarks_rule_4.2.2.2_Ensure_journald_is_configured_to_compress_large_log_files
journald_conf.push('Compress=yes') if cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_compress_large_log_files']

# xccdf_org.cisecurity.benchmarks_rule_4.2.2.3_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk
journald_conf.push('Storage=persistent') if cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk']

directory '/etc/systemd/journald.conf.d' do
  owner 'root'
  group 'root'
  mode '0755'
  action :create
end

file '/etc/systemd/journald.conf.d/CIS.conf' do
  owner 'root'
  group 'root'
  mode '0644'
  content journald_conf.join("\n")
  notifies :restart, 'service[systemd-journald]', :delayed
  action :create
end

service 'systemd-journald' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.2_Ensure_permissions_on_etccrontab_are_configured
file '/etc/crontab' do
  owner 'root'
  group 'root'
  mode '0600'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccrontab_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.3_Ensure_permissions_on_etccron.hourly_are_configured
directory '/etc/cron.hourly' do
  owner 'root'
  group 'root'
  mode '0700'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.hourly_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.4_Ensure_permissions_on_etccron.daily_are_configured
directory '/etc/cron.daily' do
  owner 'root'
  group 'root'
  mode '0700'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.daily_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.5_Ensure_permissions_on_etccron.weekly_are_configured
directory '/etc/cron.weekly' do
  owner 'root'
  group 'root'
  mode '0700'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.weekly_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.6_Ensure_permissions_on_etccron.monthly_are_configured
directory '/etc/cron.monthly' do
  owner 'root'
  group 'root'
  mode '0700'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.monthly_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.1.7_Ensure_permissions_on_etccron.d_are_configured
directory '/etc/cron.d' do
  owner 'root'
  group 'root'
  mode '0700'
  only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.d_are_configured'] }
end

# xccdf_org.cisecurity.benchmarks_rule_5.2.3_Ensure_permissions_on_SSH_private_host_key_files_are_configured
%w(ssh_host_ed25519_key ssh_host_ecdsa_key ssh_host_rsa_key).each do |k|
  file "/etc/ssh/#{k}" do
    mode '600'
    owner 'root'
    group 'root'
    only_if { cisecurity['benchmarks_rule_Ensure_permissions_on_SSH_private_host_key_files_are_configured'] }
  end
end

# xccdf_org.cisecurity.benchmarks_rule_5.4.1_Ensure_password_creation_requirements_are_configured
template '/etc/security/pwquality.conf' do
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    recipe_file:         __FILE__.to_s.split('cookbooks/').last,
    template_file:       source.to_s,
    password_min_length: 14,
    password_min_class:  4
  )
end

# xccdf_org.cisecurity.benchmarks_rule_5.7_Ensure_access_to_the_su_command_is_restricted
file '/etc/pam.d/su' do
  content lazy {
    IO.read('/etc/pam.d/su').sub(/^#(auth.*pam_wheel.so use_uid)/, '\1')
  }
  only_if { cisecurity['benchmarks_rule_Ensure_access_to_the_su_command_is_restricted'] }
end

# This removes all IPv6 sysctl options if IPv6 is disabled as it confuses the hardening cookbook
node.rm_default('sysctl', 'params', 'net', 'ipv6') unless Dir.exist?('/proc/sys/net/ipv6')

# Render sysctl configuration (leave near the bottom of this recipe)
template '/etc/sysctl.d/CIS.conf' do
  source 'sysctl.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
  variables(
    sysctl_items: sysctl_items
  )
  notifies :run, 'bash[reload_sysctl_system]', :delayed
  action :create
end

bash 'reload_sysctl_system' do
  code <<-EOH
  sysctl --system
  EOH
  action :nothing
end
