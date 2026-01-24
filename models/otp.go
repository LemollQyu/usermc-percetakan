package models

import "time"

type Otps struct {
	ID        int64     `json:"id" gorm:"primaryKey;autoIncrement"`
	UserID    int64     `json:"user_id" binding:"required"`
	Target    string    `json:"target" binding:"required,oneof=email whatsapp"`
	OtpCode   string    `json:"otp" binding:"required,numeric,len=6"`
	Type      string    `json:"type" binding:"required"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

type VerifyEmailParameter struct {
	Email string `json:"email" binding:"required,email"`
}

type VerifyPhoneParameter struct {
	Phone string `json:"phone" binding:"required,numeric,min=10,max=14"`
}

type VerifyOtpParameter struct {
	Otp string `json:"otp" binding:"required,numeric,len=6"`
}
