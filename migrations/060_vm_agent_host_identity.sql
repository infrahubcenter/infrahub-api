-- +goose Up
-- Host identity reported by the push-based VM Agent (hostname/OS family/
-- OS version/kernel version) -- one current-value set of columns on vms,
-- mirroring how vm_agent_installed/vm_agent_version already work:
-- updated on every metrics push, not stored per-snapshot, since these
-- essentially never change while the agent is running. Populated by
-- gopsutil's cross-platform host.Info() (see vm-agent/metrics.go),
-- needed for the Metrics UI's per-VM OS badge/filter and the detail
-- page's host info row.
ALTER TABLE vms
    ADD COLUMN vm_agent_os text,
    ADD COLUMN vm_agent_os_version text,
    ADD COLUMN vm_agent_kernel_version text,
    ADD COLUMN vm_agent_hostname text;

-- +goose Down
ALTER TABLE vms
    DROP COLUMN vm_agent_os,
    DROP COLUMN vm_agent_os_version,
    DROP COLUMN vm_agent_kernel_version,
    DROP COLUMN vm_agent_hostname;
