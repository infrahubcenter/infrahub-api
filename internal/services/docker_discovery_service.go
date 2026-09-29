package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/ssh"

	"vmcontrolcenter/backend/internal/database/generated"
	"vmcontrolcenter/backend/internal/pgutil"
	"vmcontrolcenter/backend/internal/repository"
)

// DockerScanResult summarizes one Scan call -- mirrors PackageScanResult's
// philosophy (Step 7): a failed or partial outcome is represented here,
// not as a Go error, so the handler can always render *something* rather
// than a generic 500.
type DockerScanResult struct {
	Status         string // SUCCESS | PARTIAL | FAILED
	DaemonStatus   DockerDaemonStatus
	ContainerCount int
	ImageCount     int
	NetworkCount   int
	VolumeCount    int
	ErrorSummary   string
}

// storedPort/storedMount give the `ports`/`mounts` jsonb columns stable,
// explicitly-named API-facing keys, independent of docker_parse.go's
// internal Go field names (spec §14/§17: safe fields only, never raw
// inspect output).
type storedPort struct {
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      int    `json:"host_port,omitempty"`
}

type storedMount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	Type        string `json:"type,omitempty"`
}

// DockerDiscoveryService orchestrates Docker daemon detection and full
// inventory discovery (spec §1-§28). Mirrors PackageService's shape:
// connect once via SSHService (Step 5, unchanged), never a second SSH
// implementation; parsing lives entirely in docker_parse.go, command
// execution in docker_client.go, never inline here.
//
// Deliberately NOT agent-branched yet (unlike DockerMetricsService/
// DockerLogCaptureService): the per-VM Docker agent's Phase 1 protocol
// (docker_agent_protocol.go) only covers container listing + stats +
// logs, not images/networks/volumes/mounts/ports -- the richer inventory
// this service discovers. Branching just the container-list sub-step
// would still require an SSH connection anyway (for everything else) and
// would report container records with materially less detail (no ports,
// mounts, or network attachment) than the SSH path already provides.
// Full agent-based inventory discovery is Phase 2's job.
type DockerDiscoveryService struct {
	store  *repository.Store
	ssh    *SSHService
	docker *DockerClient
}

// NewDockerDiscoveryService creates a DockerDiscoveryService.
func NewDockerDiscoveryService(store *repository.Store, ssh *SSHService, docker *DockerClient) *DockerDiscoveryService {
	return &DockerDiscoveryService{store: store, ssh: ssh, docker: docker}
}

// Scan runs a full Docker discovery cycle for resourceID: re-check daemon
// status (never trusting Step 5's docker_installed flag, spec §3), and if
// running, sync containers, images, networks (+ their container
// memberships), and volumes. Each of those four is independent -- one
// failing never stops the others (spec §81), and the overall run is
// PARTIAL rather than FAILED as long as at least one succeeded.
func (s *DockerDiscoveryService) Scan(ctx context.Context, resourceID uuid.UUID) (DockerScanResult, error) {
	vm, err := s.store.GetVMByResourceID(ctx, resourceID)
	if err != nil {
		return DockerScanResult{}, fmt.Errorf("load vm: %w", err)
	}

	client, connErr := s.ssh.Connect(ctx, resourceID)
	if outcomeErr := RecordConnectionOutcome(ctx, s.store, resourceID, vm.ID, connErr); outcomeErr != nil {
		return DockerScanResult{}, fmt.Errorf("record connection outcome: %w", outcomeErr)
	}
	if connErr != nil {
		sshErr := classifyConnectError(connErr)
		return s.failRun(ctx, vm.ID, DockerUnknown, "Connection failed: "+sshErr.Message)
	}
	defer client.Close()

	run, err := s.store.CreateDockerDiscoveryRun(ctx, vm.ID)
	if err != nil {
		return DockerScanResult{}, fmt.Errorf("create docker discovery run: %w", err)
	}
	scanStart := run.StartedAt.Time

	status, err := s.docker.DetectStatus(ctx, client)
	if err != nil {
		return s.completeRun(ctx, run.ID, "FAILED", DockerUnknown, 0, 0, 0, 0, "Could not determine Docker status: "+safeErrorMessage(err))
	}
	if err := s.updateDaemonStatus(ctx, vm.ID, status); err != nil {
		return DockerScanResult{}, err
	}
	if status.Status != DockerRunning {
		return s.completeRun(ctx, run.ID, "FAILED", status.Status, 0, 0, 0, 0,
			fmt.Sprintf("Docker daemon not reachable (status: %s) -- inventory scan skipped.", status.Status))
	}

	var errs []string
	succeeded := 0

	containers, containerDBIDs, containerCount, err := s.syncContainers(ctx, client, vm.ID, scanStart)
	if err != nil {
		errs = append(errs, "containers: "+safeErrorMessage(err))
	} else {
		succeeded++
	}

	imageCount, err := s.syncImages(ctx, client, vm.ID, scanStart)
	if err != nil {
		errs = append(errs, "images: "+safeErrorMessage(err))
	} else {
		succeeded++
	}

	networkDBIDs, networkCount, err := s.syncNetworks(ctx, client, vm.ID, scanStart)
	if err != nil {
		errs = append(errs, "networks: "+safeErrorMessage(err))
	} else {
		succeeded++
		// Membership rows only make sense once both sides of the
		// relationship (spec §19) are known -- if either sync above
		// failed, skip rather than write memberships against a stale
		// container/network map.
		if containerDBIDs != nil {
			if err := s.syncContainerNetworkMemberships(ctx, containers, containerDBIDs, networkDBIDs); err != nil {
				errs = append(errs, "container-network memberships: "+safeErrorMessage(err))
			}
		}
	}

	volumeCount, err := s.syncVolumes(ctx, client, vm.ID, scanStart)
	if err != nil {
		errs = append(errs, "volumes: "+safeErrorMessage(err))
	} else {
		succeeded++
	}

	runStatus := "SUCCESS"
	errorSummary := ""
	switch {
	case succeeded == 0:
		runStatus = "FAILED"
		errorSummary = "Docker inventory scan failed entirely: " + strings.Join(errs, "; ")
	case len(errs) > 0:
		runStatus = "PARTIAL"
		errorSummary = "Some Docker inventory categories could not be scanned: " + strings.Join(errs, "; ")
	}

	return s.completeRun(ctx, run.ID, runStatus, status.Status, containerCount, imageCount, networkCount, volumeCount, errorSummary)
}

// updateDaemonStatus writes the freshly-detected status/version/info to
// vms. Always called with a real detection result (DetectStatus never
// returns without classifying to a concrete status) -- a transient
// command failure returning an actual Go error is handled by the caller
// before this is reached, so this never overwrites a previously-good
// value with a guess (spec §4, mirrors UpdateVMPackageManager).
func (s *DockerDiscoveryService) updateDaemonStatus(ctx context.Context, vmRowID uuid.UUID, status DockerStatusResult) error {
	infoJSON, err := json.Marshal(dockerInfoToMap(status.Info))
	if err != nil {
		return fmt.Errorf("marshal docker info: %w", err)
	}
	if _, err := s.store.UpdateVMDockerStatus(ctx, generated.UpdateVMDockerStatusParams{
		ID: vmRowID, DockerDaemonStatus: pgutil.Text(string(status.Status)),
		DockerEngineVersion: pgutil.Text(status.Version.ServerVersion),
		DockerApiVersion:    pgutil.Text(status.Version.APIVersion),
		DockerCliVersion:    pgutil.Text(status.Version.ClientVersion),
		DockerInfo:          infoJSON,
	}); err != nil {
		return fmt.Errorf("update vm docker status: %w", err)
	}
	return nil
}

// dockerInfoToMap renders only the fields DockerInfo actually has (never
// a fabricated zero for a field the Docker install didn't report, spec
// §6) into a plain map for the docker_info jsonb column.
func dockerInfoToMap(info DockerInfo) map[string]any {
	m := map[string]any{}
	if info.StorageDriver != "" {
		m["storage_driver"] = info.StorageDriver
	}
	if info.LoggingDriver != "" {
		m["logging_driver"] = info.LoggingDriver
	}
	if info.CgroupDriver != "" {
		m["cgroup_driver"] = info.CgroupDriver
	}
	if info.CgroupVersion != "" {
		m["cgroup_version"] = info.CgroupVersion
	}
	if info.KernelVersion != "" {
		m["kernel_version"] = info.KernelVersion
	}
	if info.OperatingSystem != "" {
		m["operating_system"] = info.OperatingSystem
	}
	if info.Architecture != "" {
		m["architecture"] = info.Architecture
	}
	if info.NCPUOk {
		m["ncpu"] = info.NCPU
	}
	if info.MemTotalOk {
		m["mem_total"] = info.MemTotal
	}
	return m
}

// syncContainers upserts every discovered container and soft-removes any
// not seen this run. Returns the discovered list (needed afterward for
// membership syncing) and a Docker-container-ID -> DB-row-ID map.
func (s *DockerDiscoveryService) syncContainers(ctx context.Context, client *ssh.Client, vmRowID uuid.UUID, scanStart time.Time) ([]ContainerInfo, map[string]uuid.UUID, int, error) {
	containers, err := s.docker.ListContainers(ctx, client)
	if err != nil {
		return nil, nil, 0, err
	}

	dbIDs := make(map[string]uuid.UUID, len(containers))
	for _, c := range containers {
		repoName, tag := splitImageRef(c.Image)
		portsJSON, mountsJSON := marshalPorts(c.Ports), marshalMounts(c.Mounts)

		row, err := s.store.UpsertDockerContainer(ctx, generated.UpsertDockerContainerParams{
			VmID: vmRowID, ContainerID: c.ContainerID, Name: c.Name, Image: nonEmptyOr(repoName, c.Image),
			ImageID: pgutil.Text(c.ImageID), ImageTag: pgutil.Text(tag), Status: c.Status,
			State: pgutil.Text(c.State), Health: pgutil.Text(c.Health), Command: pgutil.Text(c.Command),
			Ports: portsJSON, Mounts: mountsJSON, RestartCount: pgutil.Int4(int32(c.RestartCount)),
			Platform: pgutil.Text(c.Platform), CreatedAtRemote: timestamptzFromPtr(c.CreatedAtRemote),
			StartedAtRemote: timestamptzFromPtr(c.StartedAtRemote),
		})
		if err != nil {
			return containers, dbIDs, len(containers), fmt.Errorf("upsert container %s: %w", c.Name, err)
		}
		dbIDs[c.ContainerID] = row.ID
	}

	if err := s.store.MarkDockerContainersRemovedSince(ctx, generated.MarkDockerContainersRemovedSinceParams{
		VmID: vmRowID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return containers, dbIDs, len(containers), fmt.Errorf("mark removed containers: %w", err)
	}

	return containers, dbIDs, len(containers), nil
}

// syncImages upserts every discovered image -- multiple tags sharing one
// image ID are kept as distinct rows (spec §22), never collapsed.
func (s *DockerDiscoveryService) syncImages(ctx context.Context, client *ssh.Client, vmRowID uuid.UUID, scanStart time.Time) (int, error) {
	images, err := s.docker.ListImages(ctx, client)
	if err != nil {
		return 0, err
	}
	for _, img := range images {
		if _, err := s.store.UpsertDockerImage(ctx, generated.UpsertDockerImageParams{
			VmID: vmRowID, Repository: img.Repository, Tag: img.Tag, ImageID: img.ImageID,
			Digest: pgutil.Text(img.Digest), SizeBytes: pgutil.Int8(img.SizeBytes),
			CreatedAtRemote: timestamptzFromPtr(img.CreatedAtRemote),
		}); err != nil {
			return len(images), fmt.Errorf("upsert image %s:%s: %w", img.Repository, img.Tag, err)
		}
	}
	if err := s.store.MarkDockerImagesRemovedSince(ctx, generated.MarkDockerImagesRemovedSinceParams{
		VmID: vmRowID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return len(images), fmt.Errorf("mark removed images: %w", err)
	}
	return len(images), nil
}

// syncNetworks upserts every discovered network. Returns a
// network-name -> DB-row-ID map (Docker network names are unique per
// daemon, so this is a safe join key for membership syncing).
func (s *DockerDiscoveryService) syncNetworks(ctx context.Context, client *ssh.Client, vmRowID uuid.UUID, scanStart time.Time) (map[string]uuid.UUID, int, error) {
	networks, err := s.docker.ListNetworks(ctx, client)
	if err != nil {
		return nil, 0, err
	}
	dbIDs := make(map[string]uuid.UUID, len(networks))
	for _, n := range networks {
		row, err := s.store.UpsertDockerNetwork(ctx, generated.UpsertDockerNetworkParams{
			VmID: vmRowID, NetworkID: n.NetworkID, Name: n.Name, Driver: pgutil.Text(n.Driver),
			Scope: pgutil.Text(n.Scope), Internal: n.Internal, Attachable: n.Attachable,
			CreatedAtRemote: timestamptzFromPtr(n.CreatedAtRemote),
		})
		if err != nil {
			return dbIDs, len(networks), fmt.Errorf("upsert network %s: %w", n.Name, err)
		}
		dbIDs[n.Name] = row.ID
	}
	if err := s.store.MarkDockerNetworksRemovedSince(ctx, generated.MarkDockerNetworksRemovedSinceParams{
		VmID: vmRowID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return dbIDs, len(networks), fmt.Errorf("mark removed networks: %w", err)
	}
	return dbIDs, len(networks), nil
}

// syncContainerNetworkMemberships replaces each discovered container's
// network-membership rows wholesale (spec §19: current-state-only, not
// history -- a hard delete-then-reinsert per container is correct here,
// unlike containers/images/networks/volumes themselves). Membership data
// (IP/gateway/MAC) is sourced from the containers' own `docker inspect`
// output, which is richer than `docker network inspect`'s member map
// (that one lacks gateway/MAC), so no second read is needed here.
func (s *DockerDiscoveryService) syncContainerNetworkMemberships(ctx context.Context, containers []ContainerInfo, containerDBIDs, networkDBIDs map[string]uuid.UUID) error {
	for _, c := range containers {
		containerDBID, ok := containerDBIDs[c.ContainerID]
		if !ok {
			continue // this container's own upsert failed; nothing to link
		}
		if err := s.store.DeleteContainerNetworkMemberships(ctx, containerDBID); err != nil {
			return fmt.Errorf("clear memberships for %s: %w", c.Name, err)
		}
		for _, n := range c.Networks {
			networkDBID, ok := networkDBIDs[n.NetworkName]
			if !ok {
				// A network this container is attached to that our
				// `docker network inspect` sweep didn't return -- skip
				// rather than guess at a network row to link.
				continue
			}
			if err := s.store.UpsertDockerContainerNetwork(ctx, generated.UpsertDockerContainerNetworkParams{
				ContainerID: containerDBID, NetworkID: networkDBID,
				IpAddress: pgutil.Text(n.IPAddress), Gateway: pgutil.Text(n.Gateway), MacAddress: pgutil.Text(n.MacAddress),
			}); err != nil {
				return fmt.Errorf("link %s to network %s: %w", c.Name, n.NetworkName, err)
			}
		}
	}
	return nil
}

// syncVolumes upserts every discovered volume.
func (s *DockerDiscoveryService) syncVolumes(ctx context.Context, client *ssh.Client, vmRowID uuid.UUID, scanStart time.Time) (int, error) {
	volumes, err := s.docker.ListVolumes(ctx, client)
	if err != nil {
		return 0, err
	}
	for _, v := range volumes {
		if _, err := s.store.UpsertDockerVolume(ctx, generated.UpsertDockerVolumeParams{
			VmID: vmRowID, VolumeName: v.Name, Driver: pgutil.Text(v.Driver), Mountpoint: pgutil.Text(v.Mountpoint),
			Scope: pgutil.Text(v.Scope), CreatedAtRemote: timestamptzFromPtr(v.CreatedAtRemote),
		}); err != nil {
			return len(volumes), fmt.Errorf("upsert volume %s: %w", v.Name, err)
		}
	}
	if err := s.store.MarkDockerVolumesRemovedSince(ctx, generated.MarkDockerVolumesRemovedSinceParams{
		VmID: vmRowID, LastDiscoveredAt: pgutil.Timestamptz(scanStart),
	}); err != nil {
		return len(volumes), fmt.Errorf("mark removed volumes: %w", err)
	}
	return len(volumes), nil
}

func (s *DockerDiscoveryService) failRun(ctx context.Context, vmRowID uuid.UUID, daemonStatus DockerDaemonStatus, errorSummary string) (DockerScanResult, error) {
	run, err := s.store.CreateDockerDiscoveryRun(ctx, vmRowID)
	if err != nil {
		return DockerScanResult{}, fmt.Errorf("create docker discovery run: %w", err)
	}
	return s.completeRun(ctx, run.ID, "FAILED", daemonStatus, 0, 0, 0, 0, errorSummary)
}

func (s *DockerDiscoveryService) completeRun(ctx context.Context, runID uuid.UUID, status string, daemonStatus DockerDaemonStatus, containerCount, imageCount, networkCount, volumeCount int, errorSummary string) (DockerScanResult, error) {
	if _, err := s.store.CompleteDockerDiscoveryRun(ctx, generated.CompleteDockerDiscoveryRunParams{
		ID: runID, Status: status, ContainerCount: pgutil.Int4(int32(containerCount)),
		ImageCount: pgutil.Int4(int32(imageCount)), NetworkCount: pgutil.Int4(int32(networkCount)),
		VolumeCount: pgutil.Int4(int32(volumeCount)), ErrorSummary: pgutil.Text(errorSummary),
	}); err != nil {
		return DockerScanResult{}, fmt.Errorf("complete docker discovery run: %w", err)
	}
	return DockerScanResult{
		Status: status, DaemonStatus: daemonStatus, ContainerCount: containerCount, ImageCount: imageCount,
		NetworkCount: networkCount, VolumeCount: volumeCount, ErrorSummary: errorSummary,
	}, nil
}

// splitImageRef splits a "repo[:tag]" reference on its final colon, but
// only when that colon comes after the final slash -- so a registry
// host:port (e.g. "registry:5000/myimage:tag") is never mistaken for a
// tag separator.
func splitImageRef(ref string) (repository, tag string) {
	if ref == "" {
		return "", ""
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, ""
}

func marshalPorts(ports []PortMapping) []byte {
	stored := make([]storedPort, 0, len(ports))
	for _, p := range ports {
		stored = append(stored, storedPort{ContainerPort: p.ContainerPort, Protocol: p.Protocol, HostIP: p.HostIP, HostPort: p.HostPort})
	}
	data, _ := json.Marshal(stored)
	return data
}

func marshalMounts(mounts []MountInfo) []byte {
	stored := make([]storedMount, 0, len(mounts))
	for _, m := range mounts {
		stored = append(stored, storedMount{Source: m.Source, Destination: m.Destination, ReadOnly: m.ReadOnly, Type: m.Type})
	}
	data, _ := json.Marshal(stored)
	return data
}

func timestamptzFromPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgutil.Timestamptz(*t)
}
