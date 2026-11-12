# Limitations

- The Linux host is a privileged Docker Desktop/LinuxKit arm64 environment,
  not a standalone production Linux server.
- CRIU `check --all` reported veth, UFFD, dirty tracking, NSID, nftables, and
  compatible-task limitations.
- Existing-client socket survival was not demonstrated; reconnection worked.
- Simultaneous multi-service atomic restoration was not run.
- Twenty independent cycles passed, but the dedicated 50/100-cycle sequences
  were not run.
- Real-checkpoint filesystem, observer, failure-injection, and DMTCP compression
  matrices remain incomplete.
- Results do not establish rollback of filesystems, remote effects, databases,
  unmanaged services, or arbitrary processes.
