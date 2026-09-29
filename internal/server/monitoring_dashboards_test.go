// This file exercises the new Monitoring/Logs Folder > Dashboard model
// (services/monitoring_dashboards.go, migrations/042_monitoring_dashboards.sql)
// that replaces the retired dashboard_folders/dashboards feature: folder/
// dashboard CRUD (Admin-only), Docker vs. Kubernetes binding, feature-
// scoped RBAC (a docker.monitor grant no longer also unlocks a
// DOCKER_LOGS dashboard, unlike the old combined-tabs Dashboard's
// either-grant-qualifies rule), resource-selection/widgets validation,
// and IDOR across projects.
package server_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"vmcontrolcenter/backend/internal/services"
)

// createMonitoringFolder is a thin wrapper around the real
// POST /api/monitoring-folders endpoint (as admin).
func (e *testEnv) createMonitoringFolder(t *testing.T, adminClient *http.Client, feature string, workspaceID uuid.UUID, name string) string {
	t.Helper()
	resp, body := e.do(t, adminClient, http.MethodPost, "/api/monitoring-folders", map[string]string{
		"feature": feature, "workspace_id": workspaceID.String(), "name": name,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create monitoring folder = %d, want 201: %v", resp.StatusCode, body)
	}
	return body["id"].(string)
}

func TestMonitoringDashboard_CreateBindsToVM(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "Docker Overview", "vm_resource_id": vmResourceID.String(),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create dashboard = %d, want 201: %v", resp.StatusCode, body)
	}
	if body["bound_resource_name"] == "" || body["bound_resource_name"] == nil {
		t.Errorf("expected a bound_resource_name, got %v", body)
	}
	if body["feature"] != "DOCKER_MONITORING" {
		t.Errorf("expected feature DOCKER_MONITORING, got %v", body["feature"])
	}
	assertAuditEventExists(t, e, "MONITORING_DASHBOARD", uuid.MustParse(body["id"].(string)), services.AuditMonitoringDashboardCreated)
}

func TestMonitoringDashboard_CreateRejectsBothOrNeitherBinding(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	clusterID, clusterResourceID := e.createK8sClusterFixture(t, project, "both-binding-cluster")
	_ = clusterID
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	// Neither binding set.
	resp, _ := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "no-binding",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with no binding = %d, want 400", resp.StatusCode)
	}

	// Both bindings set on a Docker dashboard.
	resp2, _ := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "both-binding",
		"vm_resource_id": vmResourceID.String(), "k8s_cluster_resource_id": clusterResourceID.String(),
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with both bindings = %d, want 400", resp2.StatusCode)
	}

	// Wrong-kind binding: a K8S_MONITORING dashboard given a vm_resource_id.
	resp3, _ := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "K8S_MONITORING", "name": "wrong-kind", "vm_resource_id": vmResourceID.String(),
	})
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("create K8S_MONITORING with vm_resource_id = %d, want 400", resp3.StatusCode)
	}
}

func TestMonitoringDashboard_FolderMustMatchBoundResourcePlacementAndFeature(t *testing.T) {
	e := setup(t)
	projectA := e.createWorkspace(t)
	projectB := e.createWorkspace(t)
	vmResourceID := e.createVM(t, projectB) // VM lives in project B
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	folderID := e.createMonitoringFolder(t, client, "DOCKER_MONITORING", projectA, "wrong-project-folder")

	resp, body := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "cross-project", "vm_resource_id": vmResourceID.String(),
		"monitoring_folder_id": folderID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create dashboard in cross-project folder = %d, want 400: %v", resp.StatusCode, body)
	}

	// Same project, but a folder from a different feature (Logs, not
	// Monitoring) must also be rejected.
	vmResourceID2 := e.createVM(t, projectA)
	logsFolderID := e.createMonitoringFolder(t, client, "DOCKER_LOGS", projectA, "logs-folder")
	resp2, body2 := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "wrong-feature-folder", "vm_resource_id": vmResourceID2.String(),
		"monitoring_folder_id": logsFolderID,
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("create Monitoring dashboard in a Logs folder = %d, want 400: %v", resp2.StatusCode, body2)
	}
}

// TestMonitoringDashboard_FeatureScopedRBAC_MonitorGrantDoesNotUnlockLogs
// proves the new model's single-permission-per-feature rule: unlike the
// old combined-tabs Dashboard (either a monitor OR a logs grant
// qualified), a DOCKER_LOGS dashboard now requires docker.logs
// specifically -- a docker.monitor-only grant must not see it.
func TestMonitoringDashboard_FeatureScopedRBAC_MonitorGrantDoesNotUnlockLogs(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	createResp, createBody := e.do(t, adminClient, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_LOGS", "name": "backend-logs", "vm_resource_id": vmResourceID.String(),
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create logs dashboard = %d, want 201: %v", createResp.StatusCode, createBody)
	}
	dashboardID := createBody["id"].(string)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	// A docker.monitor-only grant must not see the DOCKER_LOGS dashboard.
	getResp, _ := e.get(t, memberClient, "/api/monitoring-dashboards/"+dashboardID)
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("member with monitor-only grant viewing a logs dashboard = %d, want 404", getResp.StatusCode)
	}
	listResp, listBody := e.get(t, memberClient, "/api/monitoring-dashboards?feature=DOCKER_LOGS")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list logs dashboards = %d, want 200", listResp.StatusCode)
	}
	if dashboards, _ := listBody["dashboards"].([]any); len(dashboards) != 0 {
		t.Errorf("expected zero visible logs dashboards for a monitor-only grant, got %v", dashboards)
	}

	// Now grant docker.logs too -- the dashboard must become visible.
	e.grantDockerAccess(t, adminClient, memberID, project, services.PermDockerLogs)
	getResp2, _ := e.get(t, memberClient, "/api/monitoring-dashboards/"+dashboardID)
	if getResp2.StatusCode != http.StatusOK {
		t.Fatalf("member with logs grant viewing a logs dashboard = %d, want 200", getResp2.StatusCode)
	}
}

func TestMonitoringDashboard_K8sBinding(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, clusterResourceID := e.createK8sClusterFixture(t, project, "monitoring-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "K8S_MONITORING", "name": "Cluster Overview", "k8s_cluster_resource_id": clusterResourceID.String(),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create k8s dashboard = %d, want 201: %v", resp.StatusCode, body)
	}
	if body["bound_resource_type"] != "K8S_CLUSTER" {
		t.Errorf("expected bound_resource_type K8S_CLUSTER, got %v", body["bound_resource_type"])
	}
}

func TestMonitoringDashboard_DeleteFolderCascades(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	folderID := e.createMonitoringFolder(t, client, "DOCKER_MONITORING", project, "cascade-folder")
	createResp, createBody := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "child-dashboard", "vm_resource_id": vmResourceID.String(),
		"monitoring_folder_id": folderID,
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create dashboard = %d, want 201: %v", createResp.StatusCode, createBody)
	}
	dashboardID := createBody["id"].(string)

	delResp, _ := e.do(t, client, http.MethodDelete, "/api/monitoring-folders/"+folderID, nil)
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete folder = %d, want 200", delResp.StatusCode)
	}
	getResp, _ := e.get(t, client, "/api/monitoring-dashboards/"+dashboardID)
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("get dashboard after folder cascade-delete = %d, want 404", getResp.StatusCode)
	}
}

func TestMonitoringDashboard_ResourceSelectionAndWidgets_RoundTrip(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	vmResourceID := e.createVM(t, project)
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	createResp, createBody := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "resource-selection-test", "vm_resource_id": vmResourceID.String(),
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create dashboard = %d, want 201: %v", createResp.StatusCode, createBody)
	}
	dashboardID := createBody["id"].(string)

	// Set the Resources-step selection.
	selResp, selBody := e.do(t, client, http.MethodPut, "/api/monitoring-dashboards/"+dashboardID+"/resource-selection", map[string]any{
		"filters": []map[string]string{
			{"type": "CONTAINER", "value": "abc123"},
			{"type": "CONTAINER", "value": "def456"},
		},
	})
	if selResp.StatusCode != http.StatusOK {
		t.Fatalf("set resource selection = %d, want 200: %v", selResp.StatusCode, selBody)
	}
	selection, _ := selBody["resource_selection"].([]any)
	if len(selection) != 2 {
		t.Fatalf("expected 2 resource selection entries, got %v", selection)
	}

	// A NAMESPACE filter is illegal on a Docker dashboard.
	badResp, _ := e.do(t, client, http.MethodPut, "/api/monitoring-dashboards/"+dashboardID+"/resource-selection", map[string]any{
		"filters": []map[string]string{{"type": "NAMESPACE", "value": "default"}},
	})
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set NAMESPACE filter on Docker dashboard = %d, want 400", badResp.StatusCode)
	}

	// Set the Metrics-step widgets.
	widgetResp, widgetBody := e.do(t, client, http.MethodPut, "/api/monitoring-dashboards/"+dashboardID+"/widgets", map[string]any{
		"widgets": []string{"CPU_CHART", "MEMORY_CHART", "CONTAINER_COUNT"},
	})
	if widgetResp.StatusCode != http.StatusOK {
		t.Fatalf("set widgets = %d, want 200: %v", widgetResp.StatusCode, widgetBody)
	}
	widgets, _ := widgetBody["widgets"].([]any)
	if len(widgets) != 3 {
		t.Fatalf("expected 3 widgets, got %v", widgets)
	}

	// Widgets are not applicable to a Logs dashboard.
	logsCreateResp, logsCreateBody := e.do(t, client, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_LOGS", "name": "logs-widgets-test", "vm_resource_id": vmResourceID.String(),
	})
	if logsCreateResp.StatusCode != http.StatusCreated {
		t.Fatalf("create logs dashboard = %d, want 201: %v", logsCreateResp.StatusCode, logsCreateBody)
	}
	logsDashboardID := logsCreateBody["id"].(string)
	logsWidgetResp, _ := e.do(t, client, http.MethodPut, "/api/monitoring-dashboards/"+logsDashboardID+"/widgets", map[string]any{
		"widgets": []string{"CPU_CHART"},
	})
	if logsWidgetResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set widgets on a logs dashboard = %d, want 400", logsWidgetResp.StatusCode)
	}
}

func TestMonitoringDashboard_IDOR_MemberNeverSeesUngrantedProjectsDashboards(t *testing.T) {
	e := setup(t)
	projectA := e.createWorkspace(t)
	projectB := e.createWorkspace(t)
	vmA := e.createVM(t, projectA)
	vmB := e.createVM(t, projectB)
	adminEmail, adminPassword := e.createAdmin(t)
	adminClient := newClient()
	e.login(t, adminClient, adminEmail, adminPassword)

	_, bodyA := e.do(t, adminClient, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "project-a-dashboard", "vm_resource_id": vmA.String(),
	})
	_, bodyB := e.do(t, adminClient, http.MethodPost, "/api/monitoring-dashboards", map[string]any{
		"feature": "DOCKER_MONITORING", "name": "project-b-dashboard", "vm_resource_id": vmB.String(),
	})
	dashboardBID := bodyB["id"].(string)

	memberEmail, memberPassword, memberID := e.createMember(t)
	e.grantDockerAccess(t, adminClient, memberID, projectA, services.PermDockerMonitor)

	memberClient := newClient()
	e.login(t, memberClient, memberEmail, memberPassword)

	listResp, listBody := e.get(t, memberClient, "/api/monitoring-dashboards?feature=DOCKER_MONITORING")
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list dashboards = %d, want 200", listResp.StatusCode)
	}
	dashboards, _ := listBody["dashboards"].([]any)
	if len(dashboards) != 1 {
		t.Fatalf("expected exactly 1 visible dashboard (project A only), got %d: %v", len(dashboards), dashboards)
	}
	if dashboards[0].(map[string]any)["name"] != "project-a-dashboard" {
		t.Errorf("expected project-a-dashboard, got %v", dashboards[0])
	}

	getResp, _ := e.get(t, memberClient, "/api/monitoring-dashboards/"+dashboardBID)
	if getResp.StatusCode != http.StatusNotFound {
		t.Fatalf("member accessing an ungranted project's dashboard directly by ID = %d, want 404 (IDOR)", getResp.StatusCode)
	}
	_ = bodyA
}

func TestK8sOverviewClusterResources_RequiresK8sMonitorGrant(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, clusterResourceID := e.createK8sClusterFixture(t, project, "resources-endpoint-cluster")
	memberEmail, memberPassword, _ := e.createMember(t)
	client := newClient()
	e.login(t, client, memberEmail, memberPassword)

	resp, _ := e.get(t, client, "/api/k8s/overview/clusters/"+clusterResourceID.String()+"/resources")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("member without a grant = %d, want 404", resp.StatusCode)
	}
}

func TestK8sOverviewClusterResources_AdminSeesStructuredAgentOffline(t *testing.T) {
	e := setup(t)
	project := e.createWorkspace(t)
	_, clusterResourceID := e.createK8sClusterFixture(t, project, "admin-resources-cluster")
	adminEmail, adminPassword := e.createAdmin(t)
	client := newClient()
	e.login(t, client, adminEmail, adminPassword)

	resp, body := e.get(t, client, "/api/k8s/overview/clusters/"+clusterResourceID.String()+"/resources")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin cluster resources (no agent) = %d, want 200: %v", resp.StatusCode, body)
	}
	if body["status"] != "agent_offline" {
		t.Errorf("expected status agent_offline, got %v", body)
	}
}
