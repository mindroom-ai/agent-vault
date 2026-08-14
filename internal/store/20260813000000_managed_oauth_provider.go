package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("credential_oauth", "managed_provider") {
			return nil
		}
		return db.Exec(`ALTER TABLE credential_oauth ADD COLUMN managed_provider TEXT`).Error
	})
}
