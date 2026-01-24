package usecase

import (
	"context"
	"errors"
	"usermc/cmd/app/service"
	"usermc/infrastructure/log"
	"usermc/models"
	"usermc/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

type UserUsecase struct {
	UserService service.UserService
	JWTSecret   string
}

func NewUserUsecase(userUsecase service.UserService, jwtsecret string) *UserUsecase {
	return &UserUsecase{
		UserService: userUsecase,
		JWTSecret:   jwtsecret,
	}
}

func (uc *UserUsecase) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := uc.UserService.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (uc *UserUsecase) GetUserById(ctx context.Context, id int64) (*models.User, error) {
	user, err := uc.UserService.GetUserByUserID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (uc *UserUsecase) GetUserByPhone(ctx context.Context, phone string) (*models.User, error) {
	user, err := uc.UserService.GetUserByPhone(ctx, phone)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// fungsi untuk registrasi
func (uc *UserUsecase) RegisterUser(ctx context.Context, user *models.User) error {

	// hash password
	hashedPassword, err := utils.HashPassword(user.Password)

	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"email": user.Email,
		}).Errorf("utils.HashPassword() got error %v", err)
		return err
	}

	// insert db
	user.Password = hashedPassword

	_, err = uc.UserService.InsertUser(ctx, user)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"email": user.Email,
			"name":  user.Name,
		}).Errorf("uc.UserService.CreateNewUser() got error %v", err)
		return err
	}

	return nil
}

// fungsi untuk otp
func (uc *UserUsecase) InsertOTP(ctx context.Context, otp *models.Otps) (*models.Otps, error) {

	otps, err := uc.UserService.InsertOTP(ctx, otp)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"error_usecase": otp.UserID,
		}).Errorf("uc.UserService.InsertOTP %v", err)
		return nil, err
	}

	return otps, nil
}

func (uc *UserUsecase) GetActiveOTP(ctx context.Context, userID uint64, target string) (*models.Otps, error) {
	otp, err := uc.UserService.GetActiveOTP(ctx, userID, target)
	if err != nil {
		log.Logger.WithError(err).Error("uc.UserService.GetActiveOTP error")
		return nil, err
	}

	return otp, nil
}

func (uc *UserUsecase) SendOTPEmail(ctx context.Context, email, code string, typeOtp string) error {

	body :=
		"<h2>" + typeOtp + "</h2>" +
			"<p>Kode OTP Anda:</p>" +
			"<h1>" + code + "</h1>" +
			"<p>Berlaku selama 3 menit.</p>"

	req := models.EmailParameter{
		To:      email,
		Subject: "Kode OTP Verifikasi",
		Body:    body,
	}

	err := uc.UserService.SendEmail(ctx, req)
	if err != nil {
		log.Logger.WithError(err).Error("uc.UserService.SendEmail error")
		return err
	}

	return nil
}

func (uc *UserUsecase) SendWhatsapp(ctx context.Context, noTarget, otp, typeOtp string) (bool, error) {

	ok, err := uc.UserService.SendWhatsapp(ctx, noTarget, otp, typeOtp)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	return ok, nil
}

func (uc *UserUsecase) GetOTP(ctx context.Context, otpCode string) (*models.Otps, error) {
	otp, err := uc.UserService.GetOTP(ctx, otpCode)
	if err != nil {
		log.Logger.WithError(err).Error("uc.UserService.GetUserByOtp error")

		return nil, err
	}

	return otp, nil
}

func (uc *UserUsecase) VerifyAccount(ctx context.Context, otpID uint64, userID uint64, targetVerify string) (bool, error) {
	activeUser, err := uc.UserService.VerifyAccount(ctx, otpID, userID, targetVerify)

	if err != nil {
		log.Logger.WithError(err).Error("uc.UserService.VerifyAccount error")

		return false, err
	}

	return activeUser, nil
}

func (uc *UserUsecase) Login(ctx context.Context, param models.LoginParameter, userID int64, storedPassword string) (string, error) {

	// cek akun sudah verifikasi

	isMatch, err := utils.CheckPasswordHash(storedPassword, param.Password)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": param.User,
		}).Errorf("utils.CheckPasswordHash got error: %v", err)
	}

	if !isMatch {
		return "", errors.New("User atau password salah")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"role":    "user",
		"exp":     utils.GenerateExpiryUnix(3),
	})

	tokenString, err := token.SignedString([]byte(uc.JWTSecret))
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": param.User,
		}).Errorf("token.SignedString got error: %v", err)
		return "", err
	}

	return tokenString, nil

}

func (uc *UserUsecase) InsertSession(ctx context.Context, session *models.Session) (int64, error) {
	sessionID, err := uc.UserService.InsertSession(ctx, session)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"error_usecase": session.UserID,
		}).Errorf("uc.UserService.InsertSession %v", err)
		return 0, err
	}

	return sessionID, nil
}

func (uc *UserUsecase) UseOtp(ctx context.Context, otp string, userID uint64) (bool, error) {
	used, err := uc.UserService.UseOtp(ctx, otp, userID)
	if err != nil {
		return false, err
	}

	return used, nil
}

func (uc *UserUsecase) ChangePassword(ctx context.Context, userID int64, PasswordHashOld string, Password string) (int64, error) {

	same, err := utils.IsSamePassword(PasswordHashOld, Password)
	if err != nil {
		return 0, err
	}

	if same {
		return 0, errors.New("password baru tidak boleh sama dengan password lama")
	}

	hashingPassword, err := utils.HashPassword(Password)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": userID,
		}).Errorf("utils.HashPassword got error: %v", err)
		return 0, err
	}

	userID, err = uc.UserService.ChangePassword(ctx, userID, hashingPassword)

	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": userID,
		}).Errorf("uc.UserService.ChangePassword got error: %v", err)
		return 0, err
	}

	return userID, nil
}
func (uc *UserUsecase) LoginWithGoogle(
	ctx context.Context,
	email, googleID, name, picture string,
) (*models.User, string, error) {

	// Cari user berdasarkan email
	user, err := uc.UserService.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, "", err
	}

	// CASE A — User belum ada → buat baru
	if user.ID == 0 {

		var avatar *string
		if picture != "" {
			avatar = &picture
		}

		var gID *string
		if googleID != "" {
			gID = &googleID
		}

		newUser := &models.User{
			Email:           email,
			Name:            name,
			GoogleID:        gID,
			AvatarURL:       avatar,
			Phone:           nil,
			IsEmailVerified: true,
		}

		userID, err := uc.UserService.InsertUser(ctx, newUser)
		if err != nil {
			return nil, "", err
		}

		newUser.ID = userID
		user = newUser
	}

	// CASE B — User sudah ada
	if user.GoogleID != nil && *user.GoogleID != "" {

		// Cek apakah google_id cocok
		if *user.GoogleID != googleID {
			return nil, "", errors.New("akun google tidak sesuai dengan akun yang terdaftar")
		}

	} else {
		// google_id kosong → update
		gID := googleID
		user.GoogleID = &gID
		_ = uc.UserService.UpdateUser(ctx, user)
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     utils.GenerateExpiryUnix(3),
	})

	tokenString, err := token.SignedString([]byte(uc.JWTSecret))
	if err != nil {
		return nil, "", err
	}

	return user, tokenString, nil
}

func (uc *UserUsecase) LoginAdmin(
	ctx context.Context,
	param models.RequestLoginAdmin,
) (string, error) {

	// 1. Coba cari by email
	user, err := uc.UserService.GetUserByEmail(ctx, param.Username)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"username": param.Username,
			"error":    err.Error(),
		}).Error("failed get user by email")
		return "", err
	}

	// 2. Jika tidak ketemu, cari by phone
	if user == nil || user.ID == 0 {
		user, err = uc.UserService.GetUserByPhone(ctx, param.Username)
		if err != nil {
			log.Logger.WithFields(logrus.Fields{
				"username": param.Username,
				"error":    err.Error(),
			}).Error("failed get user by phone")
			return "", err
		}
	}

	// 3. Jika tetap tidak ketemu
	if user == nil || user.ID == 0 {
		return "", errors.New("user tidak ditemukan")
	}

	// 4. (Opsional tapi penting) cek role admin
	if user.Role != "admin" {
		return "", errors.New("user bukan admin")
	}

	isMatch, err := utils.CheckPasswordHash(user.Password, param.Password)
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": param.Password,
		}).Errorf("utils.CheckPasswordHash got error: %v", err)
	}

	if !isMatch {
		return "", errors.New("Username atau password salah")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     utils.GenerateExpiryUnix(3),
	})

	tokenString, err := token.SignedString([]byte(uc.JWTSecret))
	if err != nil {
		log.Logger.WithFields(logrus.Fields{
			"user": user.ID,
		}).Errorf("token.SignedString got error: %v", err)
		return "", err
	}

	return tokenString, nil
}
