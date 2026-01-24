package repository

import (
	"context"
	"errors"
	"fmt"
	"time"
	"usermc/infrastructure/log"
	"usermc/models"

	"gorm.io/gorm"
)

// cari email

func (r *UserRepository) FindUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := r.Database.WithContext(ctx).Where("email = ?", email).First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &user, nil
		}
		return nil, err
	}

	return &user, nil
}

// cari phone

func (r *UserRepository) FindUserByPhone(ctx context.Context, phone string) (*models.User, error) {
	var user models.User
	err := r.Database.WithContext(ctx).Where("phone = ?", phone).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &user, nil
		}
		return nil, err
	}

	return &user, nil
}

// insert user
func (r *UserRepository) InsertUser(ctx context.Context, user *models.User) (int64, error) {
	err := r.Database.WithContext(ctx).Create(user).Error

	if err != nil {
		return 0, err
	}

	return user.ID, nil
}

func (r *UserRepository) InsertOTP(ctx context.Context, otp *models.Otps) (*models.Otps, error) {
	err := r.Database.WithContext(ctx).Create(otp).Error
	if err != nil {

		return nil, err
	}

	return otp, nil
}

// cek apakah otp masih aktif
func (r *UserRepository) GetActiveOTP(ctx context.Context, userID uint64, target string) (*models.Otps, error) {
	var otp models.Otps

	err := r.Database.WithContext(ctx).
		Where("user_id = ? AND target = ? AND is_used = FALSE AND expires_at > NOW()", userID, target).
		Order("created_at DESC").
		First(&otp).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	return &otp, nil
}

// cek otp
func (r *UserRepository) GetOTP(ctx context.Context, otpCode string) (*models.Otps, error) {
	var otp models.Otps
	err := r.Database.WithContext(ctx).Where("otp_code = ?", otpCode).First(&otp).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &otp, nil
		}
		return nil, err
	}

	return &otp, nil
}

// set akun jadi aktif
func (r *UserRepository) VerifyAccount(
	ctx context.Context,
	otpID uint64,
	userID uint64,
	targetVerify string,
) (bool, error) {

	err := r.Database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		// 1. Update OTP
		if err := tx.Model(&models.Otps{}).
			Where("id = ? AND user_id = ?", otpID, userID).
			Update("is_used", true).Error; err != nil {
			return err
		}

		// 2. Tentukan update field
		var updateField string
		switch targetVerify {
		case "email":
			updateField = "is_email_verified"
		case "phone":
			updateField = "is_phone_verified"
		default:
			log.Logger.Error("invalid targetVerify: ", targetVerify)
			return fmt.Errorf("invalid targetVerify: %s", targetVerify)
		}

		// 3. Update user
		if err := tx.Model(&models.User{}).
			Where("id = ?", userID).
			Update(updateField, true).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return false, err
	}

	return true, nil
}

// cari user dengan id
func (r *UserRepository) FindUserID(ctx context.Context, userID int64) (*models.User, error) {
	var user models.User

	err := r.Database.WithContext(ctx).Where("id = ?", userID).Last(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &user, nil
		}

		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) InsertSession(ctx context.Context, session *models.Session) (int64, error) {
	err := r.Database.WithContext(ctx).Create(session).Error

	if err != nil {
		return 0, err
	}

	return session.ID, nil
}

func (r *UserRepository) UseOtp(ctx context.Context, otp string, userID uint64) (bool, error) {
	err := r.Database.WithContext(ctx).
		Model(&models.Otps{}).
		Where("otp_code = ? AND user_id = ?", otp, userID).
		Update("is_used", true).Error

	if err != nil {
		return false, err
	}

	return true, nil
}

func (r *UserRepository) ChangePassword(ctx context.Context, userID int64, hashedPassword string) (int64, error) {
	result := r.Database.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("password", hashedPassword)

	if result.Error != nil {
		return 0, result.Error
	}

	return result.RowsAffected, nil
}

// create google id / auth google
func (r *UserRepository) GetUserByGoogleID(ctx context.Context, googleID string) (*models.User, error) {
	var user models.User
	err := r.Database.WithContext(ctx).Where("google_id = ?", googleID).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, user *models.User) error {
	err := r.Database.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", user.ID).
		Updates(map[string]interface{}{
			"google_id":  user.GoogleID,
			"avatar_url": user.AvatarURL,
			"updated_at": time.Now(),
		}).Error

	return err
}
