package db

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Open() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "sqlite://./data/app.db"
	}

	var dialector gorm.Dialector
	switch {
	case strings.HasPrefix(dsn, "sqlite://"):
		path := strings.TrimPrefix(dsn, "sqlite://")
		if err := os.MkdirAll(parentDir(path), 0755); err != nil {
			return err
		}
		dialector = sqlite.Open(path)
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		dialector = postgres.Open(dsn)
	case strings.HasPrefix(dsn, "sqlserver://"):
		dialector = sqlserver.Open(dsn)
	default:
		return fmt.Errorf("unsupported DATABASE_URL scheme (use sqlite://, postgres://, or sqlserver://): %s", dsn)
	}

	var err error
	DB, err = gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return err
	}

	err = DB.AutoMigrate(
		&models.Account{},
		&models.FileShare{},
		&models.Rule{},
		&models.RuleAssignment{},
		&models.PluginConfig{},
		&models.RunLog{},
		&models.Setting{},
		&models.SyncCheckpoint{},
	)
	if err != nil {
		return err
	}
	log.Println("Database ready")
	return nil
}

// GetSetting returns the value stored for key, or defaultVal if not found.
func GetSetting(key, defaultVal string) string {
	var s models.Setting
	if err := DB.Where("key = ?", key).First(&s).Error; err == nil {
		return s.Value
	}
	return defaultVal
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
