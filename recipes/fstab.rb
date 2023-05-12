
cisecurity = node['cis_compliance']['xccdf_org']['cisecurity']
tmp = '/tmp'
tmp_options = %w()
# xccdf_org.cisecurity.benchmarks_rule_1.1.3_Ensure_noexec_option_set_on_tmp_partition
tmp_options.push('noexec') if cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_tmp_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.4_Ensure_nodev_option_set_on_tmp_partition
tmp_options.push('nodev') if cisecurity['benchmarks_rule_Ensure_nodev_option_set_on_tmp_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.5_Ensure_nosuid_option_set_on_tmp_partition
tmp_options.push('nosuid') if cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_tmp_partition']

mount tmp do
  fstype 'tmpfs'
  device tmp
  options tmp_options.join(',')
  not_if 'mount | grep /var/tmp'
  only_if { cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_tmp_partition'] || cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_tmp_partition'] || cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_tmp_partition'] }
end

dev_shm_options = %w(defaults rw)
# xccdf_org.cisecurity.benchmarks_rule_1.1.7_Ensure_noexec_option_set_on_devshm_partition
dev_shm_options.push('noexec') if cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_devshm_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.8_Ensure_nodev_option_set_on_devshm_partition
dev_shm_options.push('nodev') if cisecurity['benchmarks_rule_Ensure_nodev_option_set_on_devshm_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.9_Ensure_nosuid_option_set_on_devshm_partition
dev_shm_options.push('nosuid') if cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_devshm_partition']

mount '/dev/shm' do
  pass 0
  device 'tmpfs'
  fstype 'tmpfs'
  options dev_shm_options.join(',')
  action [:mount, :enable]
  only_if { cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_devshm_partition'] || cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_devshm_partition'] || cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_devshm_partition'] }
end

var_tmp = '/var/tmp'
var_tmp_options = %w()
# xccdf_org.cisecurity.benchmarks_rule_1.1.12_Ensure_vartmp_partition_includes_the_noexec_option
var_tmp_options.push('noexec') if cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_vartmp_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.13_Ensure_vartmp_partition_includes_the_nodev_option
var_tmp_options.push('nodev') if cisecurity['benchmarks_rule_Ensure_nodev_option_set_on_vartmp_partition']

# xccdf_org.cisecurity.benchmarks_rule_1.1.14_Ensure_vartmp_partition_includes_the_nosuid_option
var_tmp_options.push('nosuid') if cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_vartmp_partition']

mount var_tmp do
  fstype 'tmpfs'
  device tmp
  options var_tmp_options.join(',')
  not_if 'mount | grep /var/tmp'
  only_if { cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_vartmp_partition'] || cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_vartmp_partition'] || cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_vartmp_partition'] }
end
