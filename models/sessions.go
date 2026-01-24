package models

import "time"

type Session struct {
	ID           int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID       int64     `json:"user_id binding:"required"`
	RefreshToken string    `json:"refresh_token" binding:"required"`
	UserAgent    string    `json:"user_agent" binding:"required"`
	IpAddress    string    `json:"ip_address" binding:"required"`
	ExpiredAt    time.Time `json:"expired_at" binding:"required"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
}
