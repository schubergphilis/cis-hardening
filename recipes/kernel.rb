# xccdf_org.cisecurity.benchmarks_rule_1.1.1.3_Ensure_mounting_of_udf_filesystems_is_disabled
filesystems = %w()

filesystems.push('udf') if cisecurity['benchmarks_rule_Ensure_mounting_of_udf_filesystems_is_disabled']

filesystems.each do |filesystem|
  execute "rmmod #{filesystem}" do
    only_if "lsmod | grep #{filesystem}"
  end

  file "blacklist #{filesystem}" do
    path "/etc/modprobe.d/#{filesystem}.conf"
    content "install #{filesystem} /bin/true"
  end
end
