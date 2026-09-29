package services

// DatabaseCapabilities declares which performance-monitoring categories
// an engine supports (spec #81/#82) -- the frontend uses this to decide
// which tabs to render, rather than guessing from a null/absent field, or
// showing an empty "Locks" tab for Redis.
type DatabaseCapabilities struct {
	QueryMetrics bool `json:"query_metrics"`
	Locks        bool `json:"locks"`
	Replication  bool `json:"replication"`
	CacheMetrics bool `json:"cache_metrics"`
	Storage      bool `json:"storage"`
}

// CapabilitiesForType returns the fixed capability set for a database
// type. Static per engine (not per-instance/per-version): a version that
// happens to lack pg_stat_statements still reports query_metrics=true at
// the capability level (it's a PostgreSQL-class capability), and simply
// returns a "not available" warning at collection time (spec #10) --
// capabilities describe what the engine class can support, not what one
// particular instance currently has installed.
func CapabilitiesForType(dbType DatabaseType) DatabaseCapabilities {
	switch dbType {
	case DBTypePostgreSQL:
		return DatabaseCapabilities{QueryMetrics: true, Locks: true, Replication: true, CacheMetrics: true, Storage: true}
	case DBTypeMySQL, DBTypeMariaDB:
		return DatabaseCapabilities{QueryMetrics: true, Locks: true, Replication: true, CacheMetrics: true, Storage: true}
	case DBTypeMongoDB:
		return DatabaseCapabilities{QueryMetrics: false, Locks: false, Replication: true, CacheMetrics: false, Storage: true}
	case DBTypeRedis:
		return DatabaseCapabilities{QueryMetrics: false, Locks: false, Replication: true, CacheMetrics: false, Storage: false}
	default:
		return DatabaseCapabilities{}
	}
}
