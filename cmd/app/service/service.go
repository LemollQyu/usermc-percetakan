package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"

	"usermc/cmd/app/repository"
	"usermc/config"
	"usermc/infrastructure/log"
	"usermc/models"

	"github.com/sirupsen/logrus"
)

type UserService struct {
	UserRepo       repository.UserRepository
	ConfigEmail    config.EmailSecret
	ConfigWhatsapp config.WhatsappSecret
}

func NewUserService(userRepo repository.UserRepository, cfgEmail config.EmailSecret, cfgWhatsapp config.WhatsappSecret) *UserService {
	return &UserService{
		UserRepo:       userRepo,
		ConfigEmail:    cfgEmail,
		ConfigWhatsapp: cfgWhatsapp,
	}
}

func (svc *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := svc.UserRepo.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (svc *UserService) GetUserByPhone(ctx context.Context, phone string) (*models.User, error) {

	user, err := svc.UserRepo.FindUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (svc *UserService) InsertUser(ctx context.Context, user *models.User) (int64, error) {
	userID, err := svc.UserRepo.InsertUser(ctx, user)

	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (svc *UserService) InsertOTP(ctx context.Context, otp *models.Otps) (*models.Otps, error) {

	otps, err := svc.UserRepo.InsertOTP(ctx, otp)

	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"error_service": otp.UserID,
		}).Errorf("uc.UserRepo.InsertOTP %v", err)
		return nil, err
	}

	return otps, nil
}

func (svc *UserService) GetActiveOTP(ctx context.Context, userID uint64, target string) (*models.Otps, error) {

	otp, err := svc.UserRepo.GetActiveOTP(ctx, userID, target)

	if err != nil {

		return nil, err
	}

	return otp, nil
}

func (s *UserService) SendEmail(ctx context.Context, req models.EmailParameter) error {
	from := s.ConfigEmail.EmailHost
	password := s.ConfigEmail.EmailSecret
	smtpHost := s.ConfigEmail.SmtpHost
	smtpPort := s.ConfigEmail.SmtpPort

	msg := []byte("From: " + from + "\r\n" +
		"To: " + req.To + "\r\n" +
		"Subject: " + req.Subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		req.Body,
	)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{req.To}, msg)

	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"email_to": req.To,
			"service":  "SendEmail",
		}).Error("failed to send email: ", err)

		return err
	}

	return nil
}

func (svc *UserService) SendWhatsapp(ctx context.Context, number, otp, typeOtp string) (bool, error) {
	client := &http.Client{}

	// langsung build template message di service
	message := fmt.Sprintf(
		"%s – Fotocopy Nabila\n"+
			"Kode OTP Anda: %s\n"+
			"Masa berlaku: 3 Menit\n"+
			"Abaikan pesan ini jika Anda tidak meminta OTP.",
		typeOtp, otp,
	)

	data := url.Values{}
	data.Set("target", number)
	data.Set("message", message)

	req, err := http.NewRequest(
		"POST",
		"https://api.fonnte.com/send",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", svc.ConfigWhatsapp.DeviceToken)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// jika error → log dan return false
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Logger.Warnf("WA OTP Failed | status=%d | body=%s", resp.StatusCode, string(body))
		return false, nil
	}

	return true, nil
}

func (svc *UserService) GetOTP(ctx context.Context, otpCode string) (*models.Otps, error) {
	otp, err := svc.UserRepo.GetOTP(ctx, otpCode)

	if err != nil {
		return nil, err
	}

	return otp, nil
}

func (svc *UserService) VerifyAccount(ctx context.Context, otpID uint64, userID uint64, targetVerify string) (bool, error) {
	userActive, err := svc.UserRepo.VerifyAccount(ctx, otpID, userID, targetVerify)
	if err != nil {
		return false, err
	}
	return userActive, nil
}

func (svc *UserService) GetUserByUserID(ctx context.Context, userID int64) (*models.User, error) {
	user, err := svc.UserRepo.FindUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (svc *UserService) InsertSession(ctx context.Context, session *models.Session) (int64, error) {
	sessionID, err := svc.UserRepo.InsertSession(ctx, session)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"error_service": session.UserID,
		}).Errorf("uc.UserRepo.InsertSession %v", err)
		return 0, err
	}

	return sessionID, nil
}

func (svc *UserService) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	return svc.UserRepo.DeleteSessionsByUserID(ctx, userID)
}

func (svc *UserService) UseOtp(ctx context.Context, otp string, userID uint64) (bool, error) {
	used, err := svc.UserRepo.UseOtp(ctx, otp, userID)
	if err != nil {
		return false, err
	}

	return used, nil
}

func (svc *UserService) ChangePassword(ctx context.Context, userID int64, hashedPassword string) (int64, error) {
	userID, err := svc.UserRepo.ChangePassword(ctx, userID, hashedPassword)

	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (svc *UserService) UpdateUser(ctx context.Context, user *models.User) error {
	return svc.UserRepo.UpdateUser(ctx, user)
}
