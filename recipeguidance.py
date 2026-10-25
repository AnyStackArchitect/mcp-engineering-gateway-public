"""Source-linked investigation prompts, not qualified vendor signature packs.

All text is fixed program data. Evidence excerpts never become instructions.
"""

EXTRA_PACKS = {
    'proxmox': {
        'components': ('Proxmox VE', 'Corosync', 'pmxcfs', 'guest migration'),
        'reference': 'https://github.com/proxmox/pve-docs/blob/master/pvecm.adoc',
        'markers': (
            ('cluster_no_quorum', ('cluster not ready', 'no quorum'), 'Compare membership, expected votes and Corosync link evidence'),
            ('corosync_token_timeout', ('corosync', 'token', 'timeout'), 'Compare peer journals and link latency before inferring network failure'),
            ('migration_failure', ('migration', 'failed'), 'Compare task, source and destination evidence for the same migration'),
        ),
    },
    'linux': {
        'components': ('Linux', 'systemd', 'rootless Podman', 'Quadlet'),
        'reference': 'https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html',
        'markers': (
            ('quadlet_generator', ('quadlet', 'failed'), 'Compare generator diagnostics, installed Podman version and unit syntax'),
            ('container_image_pull', ('pull', 'image', 'failed'), 'Compare registry response, image digest, credentials and transport evidence locally'),
            ('service_start_timeout', ('start operation timed out',), 'Compare unit timeout with actual startup and image preparation timing'),
            ('cgroup_memory_kill', ('memory cgroup out of memory',), 'Compare cgroup limits, memory events and workload history'),
        ),
    },
    'storage': {
        'components': ('XFS', 'multipath', 'NFS', 'iSCSI'),
        'reference': 'https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_file_systems/checking-and-repairing-a-file-system__managing-file-systems',
        'markers': (
            ('xfs_metadata_corruption', ('xfs', 'metadata', 'corruption'), 'Preserve the original and compare filesystem, device and controller evidence'),
            ('multipath_path_failure', ('multipath', 'failed'), 'Compare all paths, target health and maintenance before attributing array failure'),
            ('nfs_server_not_responding', ('nfs', 'server', 'not responding'), 'Compare client retransmission, server load and packet timing'),
            ('iscsi_connection_failure', ('iscsi', 'connection', 'failed'), 'Compare session, target, transport and authentication evidence locally'),
        ),
    },
    'openshift': {
        'components': ('OpenShift', 'OADP/Velero', 'Veeam Kasten', 'CSI snapshots'),
        'reference': 'https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/backup_and_restore/oadp-application-backup-and-restore',
        'secondary_reference': 'https://docs.kasten.io/9.0.0/operating/support/',
        'markers': (
            ('velero_backup_failure', ('velero', 'backup', 'failed'), 'Compare backup CR status, controller logs, storage location and plugin versions'),
            ('kasten_action_failure', ('kasten', 'action', 'failed'), 'Compare action details, policy, profile and service evidence locally'),
            ('csi_snapshot_failure', ('snapshot', 'csi', 'failed'), 'Compare snapshot CRs, driver capability and storage class versions'),
        ),
    },
    'identity': {
        'components': ('Kerberos', 'Active Directory', 'DNS'),
        'reference': 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance',
        'secondary_reference': 'https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics',
        'markers': (
            ('kerberos_ticket_modified', ('krb_ap_err_modified',), 'Compare ticket target, SPN uniqueness and service account configuration locally'),
            ('kerberos_clock_skew', ('krb_ap_err_skew',), 'Compare independently measured client, service and KDC clock offsets'),
            ('dns_servfail', ('dns', 'servfail'), 'Compare authoritative response, recursion, validation and packet evidence'),
            ('domain_controller_unavailable', ('domain controller', 'could not be contacted'), 'Compare DNS locator records, reachability and service readiness evidence'),
        ),
    },
}

# Documentation versions are source context, not supported deployment versions.
GUIDANCE = {
    'vmware': {
        'reference_context': 'Broadcom ESXi log-location and VCF collection guidance',
        'required_evidence': ('ESXi/vCenter/VCF build inventory', 'host and management journals', 'storage and snapshot history'),
        'candidate_explanations': ('storage path interruption', 'management service or lifecycle precondition failure'),
        'falsification_checks': ('Compare healthy peer logs and successful operations in the same interval', 'Disconfirm same-task and endpoint identity mismatches before linking symptoms'),
    },
    'veeam': {
        'reference_context': 'VBR logging guide; deployment version not supplied',
        'required_evidence': ('VBR and component build inventory', 'backup job and hypervisor session logs', 'repository and proxy evidence'),
        'candidate_explanations': ('snapshot or application-consistency precondition failure', 'proxy repository or Cloud Connect transport interruption'),
        'falsification_checks': ('Compare the same session with an unaffected job and selected proxy', 'Check whether snapshot or repository operations succeeded despite the marker'),
    },
    'hyperv': {
        'reference_context': 'Microsoft Hyper-V high-availability troubleshooting guidance',
        'required_evidence': ('Windows Server and cluster build inventory', 'VMMS and FailoverClustering logs', 'CSV and migration evidence'),
        'candidate_explanations': ('cluster communication or resource dependency failure', 'storage or migration precondition failure'),
        'falsification_checks': ('Compare node membership and CSV availability across peers', 'Exclude expected maintenance and events from another virtual machine'),
    },
    'nutanix': {
        'reference_context': 'Foundation API reference; AHV/Foundation build not supplied',
        'required_evidence': ('AHV AOS and Foundation versions', 'Foundation/Phoenix and CVM journals', 'boot and management network evidence'),
        'candidate_explanations': ('boot staging or reachability precondition failure', 'CVM service startup or storage readiness failure'),
        'falsification_checks': ('Compare the same node and imaging phase with successful peers', 'Check successful heartbeat and service recovery evidence after the marker'),
    },
    'proxmox': {
        'reference_context': 'Proxmox pve-docs cluster-manager source; moving master reference',
        'required_evidence': ('PVE Corosync and kernel versions', 'membership and vote snapshots', 'peer journals and migration task identity'),
        'candidate_explanations': ('missing quorum membership', 'transport delay or migration precondition failure'),
        'falsification_checks': ('Compare votes and peer membership at the event time', 'Distinguish planned node shutdown and unrelated migration tasks'),
    },
    'linux': {
        'reference_context': 'Podman latest Quadlet reference; installed version unverified',
        'required_evidence': ('kernel systemd and Podman versions', 'unit generator and journal evidence', 'cgroup and image identity snapshots'),
        'candidate_explanations': ('generator version or unit syntax mismatch', 'startup budget image preparation or memory pressure'),
        'falsification_checks': ('Compare generated unit and syntax against installed-version documentation', 'Compare successful startup, memory counters and image readiness before assigning cause'),
    },
    'storage': {
        'reference_context': 'RHEL 9 filesystem guide; other distributions and versions unqualified',
        'required_evidence': ('kernel filesystem and storage tool versions', 'filesystem and block device journals', 'path target and transport snapshots'),
        'candidate_explanations': ('filesystem metadata damage', 'path transport target or capacity interruption'),
        'falsification_checks': ('Distinguish a single path event from loss of all usable paths', 'Compare preserved image and controller evidence; a repair exit code alone is insufficient'),
    },
    'openshift': {
        'reference_context': 'OpenShift 4.18 OADP and Kasten 9.0.0 documentation; deployment compatibility unverified',
        'required_evidence': ('OpenShift OADP Kasten and CSI versions', 'backup restore action and policy identities', 'controller logs CR status and storage classes'),
        'candidate_explanations': ('plugin or snapshot capability mismatch', 'backup location resource or policy precondition failure'),
        'falsification_checks': ('Compare supported version matrices and actual storage class capability evidence', 'Distinguish another policy or action and verify restore results separately from backup success'),
    },
    'identity': {
        'reference_context': 'Microsoft Kerberos guidance and Windows DNS diagnostics; platform build unverified',
        'required_evidence': ('client service and domain controller versions', 'sanitized authentication status and SPN inventory', 'DNS and independently measured clock evidence'),
        'candidate_explanations': ('ticket target service identity or key mismatch', 'clock DNS or domain controller availability issue'),
        'falsification_checks': ('Compare expected SPN and target identity with a successful authentication', 'Disconfirm independent clock and DNS assumptions; packet proximity alone is not authentication cause'),
    },
}
