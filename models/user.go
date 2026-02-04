package models

import "time"

type User struct {
	ID              int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	Username        string    `json:"username" gorm:"column:username"`
	Name            string    `json:"name" gorm:"column:name"`
	Email           string    `json:"email"`
	Phone           *string   `json:"phone"`
	AvatarURL       *string   `json:"avatar_url"`
	Password        string    `json:"password"`
	GoogleID        *string   `json:"google_id"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsPhoneVerified bool      `json:"is_phone_verified"`
	Role            string    `json:"role"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RegisterParameter struct {
	Username        string `json:"username" binding:"required,min=3,max=30"`
	Name            string `json:"name" binding:"required,min=3,max=50"`
	Email           string `json:"email" binding:"required,email"`
	Phone           string `json:"phone" binding:"required,numeric,min=9,max=15"`
	Password        string `json:"password" binding:"required,min=8,max=20"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}

type LoginParameter struct {
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required,min=8,max=20"`
}

type ForgotPasswordParameter struct {
	User string `json:"user" binding:"required"`
}

type NewPassword struct {
	UserID int64 `json:"user_id" binding:"required"`
	// TokenPassword   string `json:"token_password" binding:"required"`
	Password        string `json:"password" binding:"required,min=8,max=20"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}
