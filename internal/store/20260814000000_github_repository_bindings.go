package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		createdAtType := "TIMESTAMPTZ"
		if db.Name() == "sqlite" {
			createdAtType = "TEXT"
		}
		return db.Exec(`CREATE TABLE github_repository_bindings (
    vault_id         TEXT PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
    worker_key_hash  TEXT NOT NULL UNIQUE,
    repository_id    TEXT NOT NULL UNIQUE,
    organization     TEXT NOT NULL,
    repository_name  TEXT NOT NULL,
    permissions_json TEXT NOT NULL CHECK (permissions_json = '{"contents":"write"}'),
    created_at       ` + createdAtType + ` NOT NULL,
    UNIQUE (organization, repository_name)
)`).Error
	})
}
