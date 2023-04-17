default['cis_compliance'].tap do |cis_compliance|
  # login.defs settings
  cis_compliance['env']['umask'] = '007'
  cis_compliance['env']['extra_user_paths'] = []

  # Remediation toggles (based on naming of the Inspec controls)
  # SBP controls
  cis_compliance['sbp_configure_kernel_to_only_allow_signed_modules'] = true
  cis_compliance['sbp_kernel_is_not_tainted'] = true
  cis_compliance['sbp_kernel_only_allows_signed_modules'] = true
  cis_compliance['sbp_mrepos_are_not_older_than_6_weeks'] = true

  # CIS templates
  cis_compliance['xccdf_org']['cisecurity'].tap do |cisecurity|
    cisecurity['benchmarks_rule_Create_custom_authselect_profile'] = true
    cisecurity['benchmarks_rule_Disable_USB_Storage'] = true
    cisecurity['benchmarks_rule_Ensure_DCCP_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_ICMP_redirects_are_not_accepted'] = true
    cisecurity['benchmarks_rule_Ensure_IP_forwarding_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_IPv6_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_IPv6_redirects_are_not_accepted'] = true
    cisecurity['benchmarks_rule_Ensure_IPv6_router_advertisements_are_not_accepted'] = true
    # cisecurity['benchmarks_rule_Ensure_NFS_and_RPC_are_not_enabled'] = true
    cisecurity['benchmarks_rule_Ensure_RDS_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_Reverse_Path_Filtering_is_enabled'] = true
    cisecurity['benchmarks_rule_Ensure_SCTP_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_Idle_Timeout_Interval_is_configured'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_MaxSessions_is_set_to_4_or_less'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_MaxStartups_is_configured'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_PermitUserEnvironment_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_X11_forwarding_is_disabled'] = true
    # cisecurity['benchmarks_rule_Ensure_SSH_access_is_limited'] = true
    cisecurity['benchmarks_rule_Ensure_SSH_warning_banner_is_configured'] = true
    cisecurity['benchmarks_rule_Ensure_TCP_SYN_Cookies_is_enabled'] = true
    cisecurity['benchmarks_rule_Ensure_TIPC_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_X_Window_System_is_not_installed'] = true
    cisecurity['benchmarks_rule_Ensure_RPC_is_not_enabled'] = true
    cisecurity['benchmarks_rule_Ensure_access_to_the_su_command_is_restricted'] = true
    cisecurity['benchmarks_rule_Ensure_address_space_layout_randomization_ASLR_is_enabled'] = true
    cisecurity['benchmarks_rule_Ensure_all_users_home_directories_exist'] = true
    cisecurity['benchmarks_rule_Ensure_atcron_is_restricted_to_authorized_users'] = true
    cisecurity['benchmarks_rule_Ensure_authselect_includes_with-faillock'] = true
    cisecurity['benchmarks_rule_Ensure_bogus_ICMP_responses_are_ignored'] = true
    cisecurity['benchmarks_rule_Ensure_broadcast_ICMP_requests_are_ignored'] = true
    cisecurity['benchmarks_rule_Ensure_core_dumps_are_restricted'] = true
    cisecurity['benchmarks_rule_Ensure_default_user_shell_timeout_is_900_seconds_or_less'] = true
    # cisecurity['benchmarks_rule_Ensure_default_user_umask_is_027_or_more_restrictive'] = true
    cisecurity['benchmarks_rule_Ensure_gpgcheck_is_globally_activated'] = true
    # cisecurity['benchmarks_rule_Ensure_inactive_password_lock_is_30_days_or_less'] = true
    cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_compress_large_log_files'] = true
    cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_send_logs_to_rsyslog'] = true
    cisecurity['benchmarks_rule_Ensure_journald_is_configured_to_write_logfiles_to_persistent_disk'] = true
    cisecurity['benchmarks_rule_Ensure_local_login_warning_banner_is_configured_properly'] = true
    cisecurity['benchmarks_rule_Ensure_lockout_for_failed_password_attempts_is_configured'] = true
    cisecurity['benchmarks_rule_Ensure_message_of_the_day_is_configured_properly'] = true
    # cisecurity['benchmarks_rule_Ensure_minimum_days_between_password_changes_is_7_or_more'] = true
    cisecurity['benchmarks_rule_Ensure_nodev_option_set_on_devshm_partition'] = true
    cisecurity['benchmarks_rule_Ensure_noexec_option_set_on_devshm_partition'] = true
    cisecurity['benchmarks_rule_Ensure_nosuid_option_set_on_devshm_partition'] = true
    cisecurity['benchmarks_rule_Ensure_only_approved_MAC_algorithms_are_used'] = true
    cisecurity['benchmarks_rule_Ensure_packet_redirect_sending_is_disabled'] = true
    cisecurity['benchmarks_rule_Ensure_password_creation_requirements_are_configured'] = true
    # cisecurity['benchmarks_rule_Ensure_password_expiration_is_365_days_or_less'] = false
    cisecurity['benchmarks_rule_Ensure_password_reuse_is_limited'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_SSH_private_host_key_files_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_bootloader_config_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.d_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.daily_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.hourly_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.monthly_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccron.weekly_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_permissions_on_etccrontab_are_configured'] = true
    cisecurity['benchmarks_rule_Ensure_root_PATH_integrity'] = true
    cisecurity['benchmarks_rule_Ensure_secure_ICMP_redirects_are_not_accepted'] = true
    cisecurity['benchmarks_rule_Ensure_source_routed_packets_are_not_accepted'] = true
    cisecurity['benchmarks_rule_Ensure_sudo_commands_use_pty'] = true
    cisecurity['benchmarks_rule_Ensure_sudo_log_file_exists'] = true
    cisecurity['benchmarks_rule_Ensure_suspicious_packets_are_logged'] = true
    cisecurity['benchmarks_rule_Ensure_system-wide_crypto_policy_is_not_legacy'] = true
    cisecurity['benchmarks_rule_Ensure_system_accounts_are_non-login'] = true
    cisecurity['benchmarks_rule_Ensure_telnet_client_is_not_installed'] = true
    cisecurity['benchmarks_rule_Ensure_tmp_is_configured'] = true
    cisecurity['benchmarks_rule_Ensure_users_home_directories_permissions_are_750_or_more_restrictive'] = true
    cisecurity['benchmarks_rule_Ensure_users_own_their_home_directories'] = true
    cisecurity['benchmarks_rule_Ensure_wireless_interfaces_are_disabled'] = true
    cisecurity['benchmarks_rule_Select_authselect_profile'] = true
  end
end
