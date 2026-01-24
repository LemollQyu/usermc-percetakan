package repository

import "gorm.io/gorm"

type UserRepository struct {
	Database *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		Database: db,
	}
}
