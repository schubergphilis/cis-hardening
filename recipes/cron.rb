cisecurity = node['cis_compliance']['xccdf_org']['cisecurity']

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

# xccdf_org.cisecurity.benchmarks_rule_5.1.8_Ensure_cron_is_restricted_to_authorized_users
file '/etc/cron.allow' do
  action :create
  mode '600'
  owner 'root'
  group 'root'
  only_if { cisecurity['benchmarks_rule_Ensure_cron_is_restricted_to_authorized_users'] }
end

file '/etc/cron.deny' do
  action :delete
end

package 'cronie' do
  action :remove
end
