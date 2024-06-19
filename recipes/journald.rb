cisecurity = node['cis_compliance']['xccdf_org']['cisecurity']

# xccdf_org.cisecurity.benchmarks_rule_4.2.2.2_Ensure_journald_is_configured_to_compress_large_log_files
replace_or_add 'journald compress' do
  path '/etc/systemd/journald.conf'
  pattern '#Compress.*'
  line 'Compress=yes'
  only_if { cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_compress_large_log_files'] }
end

# xccdf_org.cisecurity.benchmarks_rule_4.2.2.3_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk
replace_or_add 'journald compress' do
  path '/etc/systemd/journald.conf'
  pattern '#Storage.*'
  line 'Storage=persistent'
  only_if { cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk'] }
end
