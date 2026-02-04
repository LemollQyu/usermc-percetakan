package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"usermc/cmd/app/usecase"
	"usermc/infrastructure/log"
	"usermc/models"
	"usermc/utils"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"golang.org/x/oauth2"
)

type UserHandler struct {
	UserUsecase usecase.UserUsecase
	GoogleOAuth *oauth2.Config
}

func NewUserHandler(userUsecase usecase.UserUsecase, g *oauth2.Config) *UserHandler {
	return &UserHandler{
		UserUsecase: userUsecase,
		GoogleOAuth: g,
	}
}

func (h *UserHandler) Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status-api": "siap",
	})
}

// handler registrasi
func (h *UserHandler) Register(c *gin.Context) {
	var param models.RegisterParameter

	//  cek valid tidak parameter

	if err := c.ShouldBindJSON(&param); err != nil {

		// Cek apakah error dari validator
		var ve validator.ValidationErrors

		if errors.As(err, &ve) {

			// Ambil error pertama
			fe := ve[0]

			// bikin pesan error custom
			errorMsg := fmt.Sprintf(
				"Field '%s' failed on the '%s' rule",
				fe.Field(),
				fe.Tag(),
			)
			log.Logger.Info("Bad request", errorMsg)

			// return ke response
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": errorMsg,
			})
			return
		}

		// fallback kalau error lain (misal JSON rusak)
		log.Logger.Info("Invalid Parameter")
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": err.Error(),
		})
		return
	}

	// cek email sudah gunakan atau belum

	userEmail, err := h.UserUsecase.GetUserByEmail(c.Request.Context(), param.Email)
	if err != nil {
		log.Logger.Info("Error internal server h.UserUsecase.GetUserByEmail", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if userEmail.ID != 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Email sudah digunakan",
			"email":         param.Email + " sudah digunakan",
		})
		return
	}

	// cek phone sudah digunakan
	userPhone, err := h.UserUsecase.GetUserByPhone(c.Request.Context(), param.Phone)
	if err != nil {
		log.Logger.Info("Error internal server h.UserUsecase.GetUserByPhone", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if userPhone.ID != 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Phone sudah digunakan",
			"phone":         param.Phone + " sudah digunakan",
		})
		return
	}

	// insert user ke db
	phone := param.Phone
	newPhone := &phone
	err = h.UserUsecase.RegisterUser(c.Request.Context(), &models.User{
		Username: param.Username,
		Name:     param.Name,
		Email:    param.Email,
		Phone:    newPhone,
		Password: param.Password,
	})

	if err != nil {
		log.Logger.Info("Error internal server h.UserUsecase.RegisterUser", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User berhasil mendaftar",
		"note":    "Silahkan verifikasi akun",
	})

}

// handler verifikasi dengan email
func (h *UserHandler) VerifyEmail(c *gin.Context) {

	var param models.VerifyEmailParameter

	// cek valid kah parameternya
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	// cek email apakah sama dengan yang didaftarkan
	user, err := h.UserUsecase.GetUserByEmail(c.Request.Context(), param.Email)
	if err != nil {
		log.Logger.Info("Error internal server h.UserUsecase.GetUserByEmail", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Email tidak ditemukan",
			"email":         param.Email + " belum registrasi",
		})
		return
	}

	// cek otp sudah digunakan atau belum
	// juga apakah sudah expires

	otpId, err := h.UserUsecase.GetActiveOTP(c.Request.Context(), uint64(user.ID), "email")
	if err != nil {
		log.Logger.Info("h.UserUsecase.GetActiveOTP", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if otpId != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP masih aktif. Silakan cek kembali email Anda.",
		})
		return
	}

	// cek email sudah aktif apa belum

	if user.IsEmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Email akun sudah aktif.",
		})
		return
	}

	// generate otp code

	otpCode := utils.GenerateOTP(6)

	otp, err := h.UserUsecase.InsertOTP(c.Request.Context(), &models.Otps{
		UserID:    user.ID,
		Target:    "email",
		OtpCode:   otpCode,
		ExpiresAt: utils.ExpireOTP3Minutes(),
		Type:      "Verification_email",
	})

	if err != nil {
		log.Logger.Info("h.UserUsecase.InsertOTP", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	// kirim kode otp ke email
	err = h.UserUsecase.SendOTPEmail(c.Request.Context(), user.Email, otpCode, otp.Type)
	if err != nil {
		log.Logger.WithError(err).Error("failed to send OTP email")

		c.JSON(500, gin.H{
			"error_message": "Gagal mengirim email",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Kode verifikasi telah dikirim ke email " + user.Email,
		"expired": utils.SecondsUntil(otp.ExpiresAt),
	})

}

// handler verifikasi otp

func (h *UserHandler) VerifyOTPEmail(c *gin.Context) {
	var param models.VerifyOtpParameter

	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	if len(param.Otp) != 6 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "OTP harus 6 digit",
		})
		return
	}

	otp, err := h.UserUsecase.GetOTP(c.Request.Context(), param.Otp)
	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.GetOTP, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})
		return
	}

	// cek 2 lapis

	if otp.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	if otp.OtpCode != param.Otp {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	// cek otp hanya unutk email

	if otp.Target != "email" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Diperuntukan untuk otp aktivasi email",
		})
		return
	}

	if otp.Type != "Verification_email" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Diperuntukan untuk otp aktivasi email",
		})
		return
	}

	if otp.IsUsed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "sudah digunakan",
		})
		return
	}

	if time.Now().After(otp.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP sudah kadaluarsa",
			"note":          "Silahkan resend ulang!",
		})
		return
	}

	// jika otp berhasil aktifkan akun
	activeUser, err := h.UserUsecase.VerifyAccount(c.Request.Context(), uint64(otp.ID), uint64(otp.UserID), "email")
	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.VerifyAccount, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Akun berhasil di aktifkan",
		"status_account": activeUser,
	})

}

// func verifikasi dengan phone
func (h *UserHandler) VerifyPhone(c *gin.Context) {

	var param models.VerifyPhoneParameter

	// cek valid tidak parameter inputan user
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	// cek phone terdaftar belum
	user, err := h.UserUsecase.GetUserByPhone(c.Request.Context(), param.Phone)
	if err != nil {
		log.Logger.Info("Error internal server h.UserUsecase.GetUserByPhone", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Phone tidak ditemukan",
			"Phone":         param.Phone + " belum registrasi",
		})
		return
	}
	// cek otp yang terkirim apakah sudah kadaluarsa jika iya, boleh kirim ulang

	otpId, err := h.UserUsecase.GetActiveOTP(c.Request.Context(), uint64(user.ID), "whatsapp")
	if err != nil {
		log.Logger.Info("h.UserUsecase.GetActiveOTP", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if otpId != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP masih aktif. Silakan cek kembali whatsapp Anda.",
		})
		return
	}

	//cek verifikasi akun sudah aktif belum

	if user.IsPhoneVerified {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Nomor akun sudah aktif",
			"note":          "silahkan login",
		})

		return
	}

	// cek otp sudah digunakan apa belum

	// insert otp
	otpCode := utils.GenerateOTP(6)

	otp, err := h.UserUsecase.InsertOTP(c.Request.Context(), &models.Otps{
		UserID:    user.ID,
		Target:    "whatsapp",
		OtpCode:   otpCode,
		ExpiresAt: utils.ExpireOTP3Minutes(),
		Type:      "Verification_whatsapp",
	})

	if err != nil {
		log.Logger.Info("h.UserUsecase.InsertOTP", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	// kirim pesan whatsapp ke no phone tersebut

	ok, err := h.UserUsecase.SendWhatsapp(c.Request.Context(), param.Phone, otp.OtpCode, otp.Type)

	if err != nil {
		log.Logger.WithError(err).Error("SendWhatsapp failed")

		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "Gagal mengirim WhatsApp",
		})
		return
	}

	if !ok {
		log.Logger.WithError(err).Error("SendWhatsapp failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "Gagal mengirim WhatsApp",
		})
		return
	}

	// tampilkan pesan
	c.JSON(http.StatusOK, gin.H{
		"message":  "Kode verifikasi telah dikirim ke no " + param.Phone,
		"expired":  utils.SecondsUntil(otp.ExpiresAt),
		"terkirim": ok,
	})
}

// verifikasi otp phone

func (h *UserHandler) VerifyOTPPhone(c *gin.Context) {

	var param models.VerifyOtpParameter

	// cek valid kah parameternya
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	// ambil otpnya
	otp, err := h.UserUsecase.GetOTP(c.Request.Context(), param.Otp)
	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.GetOTP, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	// cek otp salah
	// cek 2 lapis

	if otp.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	if otp.OtpCode != param.Otp {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	// cek otp hanya unutk phone

	if otp.Target != "whatsapp" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Diperuntukan untuk otp aktivasi phone",
		})
		return
	}

	if otp.Type != "Verification_whatsapp" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Diperuntukan untuk otp aktivasi phone",
		})
		return
	}

	// cek otp sudah kadaluarsa belum

	if time.Now().After(otp.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP sudah kadaluarsa",
			"note":          "Silahkan resend ulang!",
		})
		return
	}

	// cek otp sudah digunakan belum

	if otp.IsUsed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "sudah digunakan",
		})
		return
	}

	// aktifkan nomor akun
	// jika otp berhasil aktifkan akun
	activeUser, err := h.UserUsecase.VerifyAccount(c.Request.Context(), uint64(otp.ID), uint64(otp.UserID), "phone")
	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.VerifyAccount, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Akun berhasil di aktifkan",
		"status_account": activeUser,
	})

}

// login
func (h *UserHandler) Login(c *gin.Context) {

	// untuk login perlu validasi dari emailnya atau phone itu bisa terakses
	// meskipun salah satu sudah terverifikasi

	var param models.LoginParameter

	// BIND INPUT
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})
		return
	}

	// VALIDASI PASSWORD MINIMAL 8 KARAKTER
	if len(param.Password) < 8 {
		log.Logger.Info("Invalid Input")
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Password minimal 8 karakter",
		})
		return
	}

	ctx := c.Request.Context()
	var user *models.User

	// 1. Cari user berdasarkan email atau phone
	user, err := h.UserUsecase.GetUserByEmail(ctx, param.User)
	if err != nil {
		log.Logger.Info("Error server: GetUserByEmail", err)
	}
	if user == nil || user.ID == 0 {
		// Jika tidak ketemu by email → cari by phone
		user, err = h.UserUsecase.GetUserByPhone(ctx, param.User)
		if err != nil {
			log.Logger.Info("Error server: GetUserByPhone", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_message": "Internal Server Error",
			})
			return
		}
	}

	// Jika tetap tidak ditemukan
	if user == nil || user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Email atau Phone belum terdaftar",
		})
		return
	}

	// 2. Cek minimal salah satu verifikasi
	if !user.IsEmailVerified && !user.IsPhoneVerified {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Akun belum diverifikasi. Verifikasi email atau phone terlebih dahulu.",
		})
		return
	}

	// login dan kirim token
	token, err := h.UserUsecase.Login(c.Request.Context(), param, user.ID, user.Password)
	if err != nil {
		log.Logger.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_message": "User atau password salah",
		})

		return
	}

	// insert sessionnya

	tokenAccess, err := utils.GenerateRandomToken()
	if err != nil {
		log.Logger.Errorf("Kesalahan server %v", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "Kesalahan server",
		})

		return
	}

	_, err = h.UserUsecase.InsertSession(c.Request.Context(), &models.Session{
		UserID:       user.ID,
		UserAgent:    utils.GetUserAgent(c.Request),
		IpAddress:    utils.GetClientIP(c.Request),
		RefreshToken: tokenAccess,
		ExpiredAt:    utils.GenerateExpiry(24 * 7),
	})

	if err != nil {
		log.Logger.Errorf("InsertSession error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "Kesalahan server saat membuat session",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login Berhasil",
		"token":   token,
	})
}

func (h *UserHandler) GetUserInfo(c *gin.Context) {

	// ambil user_id dari middleware
	userIDAny, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_message": "unauthorized",
		})
		return
	}

	userID, ok := userIDAny.(int64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_message": "invalid token",
		})
		return
	}

	user, err := h.UserUsecase.GetUserById(c.Request.Context(), userID)
	if err != nil {
		log.Logger.Errorf("GetUserById error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "internal server error",
		})
		return
	}

	if user == nil || user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error_message": "user not found",
		})
		return
	}

	// Username dari DB; fallback email/phone hanya jika kosong (e.g. user Google), jangan pakai name
	username := user.Username
	if username == "" {
		username = user.Email
	}
	if username == "" && user.Phone != nil {
		username = *user.Phone
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         user.ID,
		"username":  username,
		"name":      user.Name,
		"email":     user.Email,
		"phone":     user.Phone,
		"avatar_url": user.AvatarURL,
	})
}

// google auth
func (h *UserHandler) GoogleAuth(c *gin.Context) {
	url := h.GoogleOAuth.AuthCodeURL("state-token")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// callback google auth
func (h *UserHandler) GoogleAuthCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error_message": "missing code"})
		return
	}

	token, err := h.GoogleOAuth.Exchange(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error_message": "google exchange error"})
		return
	}

	client := h.GoogleOAuth.Client(context.Background(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_message": "failed to get userinfo"})
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_message": "decode error"})
		return
	}

	_, tokenString, err := h.UserUsecase.LoginWithGoogle(
		c.Request.Context(),
		googleUser.Email,
		googleUser.ID,
		googleUser.Name,
		googleUser.Picture,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login dengan google, berhasil",
		"token":   tokenString,
	})
}

// lupa password
func (h *UserHandler) ForgotPassword(c *gin.Context) {

	var param models.ForgotPasswordParameter

	if err := c.ShouldBindJSON(&param); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid parameter",
		})
		return
	}

	ctx := c.Request.Context()

	// 1. Cari user melalui email atau phone
	user, err := h.UserUsecase.GetUserByEmail(ctx, param.User)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_message": "Internal Server Error"})
		return
	}

	target := ""

	if user.ID != 0 {
		target = "email"
	} else {
		user, err = h.UserUsecase.GetUserByPhone(ctx, param.User)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error_message": "Internal Server Error"})
			return
		}

		if user.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": "Email atau phone belum terdaftar",
			})
			return
		}

		target = "whatsapp"
	}

	// 2. CEK APAKAH ADA OTP AKTIF
	otpId, err := h.UserUsecase.GetActiveOTP(ctx, uint64(user.ID), target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})
		return
	}

	if otpId != nil {

		if target == "email" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": "OTP masih aktif. Silakan cek kembali Email Anda.",
			})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": "OTP masih aktif. Silakan cek kembali WhatsApp Anda.",
			})
		}
		return
	}

	// 3. Generate OTP BARU
	otpCode := utils.GenerateOTP(6)

	// 4. Insert OTP
	otp, err := h.UserUsecase.InsertOTP(ctx, &models.Otps{
		UserID:    user.ID,
		Target:    target,
		OtpCode:   otpCode,
		ExpiresAt: utils.ExpireOTP3Minutes(),
		Type:      "Forgot_password",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error_message": err.Error()})
		return
	}

	// 5. Kirim OTP
	if target == "email" {

		err = h.UserUsecase.SendOTPEmail(ctx, user.Email, otpCode, otp.Type)
		if err != nil {
			c.JSON(500, gin.H{"error_message": "Gagal mengirim email"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Kode verifikasi telah dikirim ke email " + user.Email,
			"expired": utils.SecondsUntil(otp.ExpiresAt),
		})

	} else { // WhatsApp

		ok, err := h.UserUsecase.SendWhatsapp(ctx, utils.StringOrEmpty(user.Phone), otpCode, otp.Type)
		if err != nil || !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error_message": "Gagal mengirim WhatsApp"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "Kode verifikasi telah dikirim ke no " + utils.StringOrEmpty(user.Phone),
			"expired":  utils.SecondsUntil(otp.ExpiresAt),
			"terkirim": ok,
		})
	}
}

func (h *UserHandler) VerifyOTPForgotPassword(c *gin.Context) {
	var param models.VerifyOtpParameter

	// cek valid kah parameternya
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	// ambil otpnya
	otp, err := h.UserUsecase.GetOTP(c.Request.Context(), param.Otp)
	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.GetOTP, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	// cek otp salah
	// cek 2 lapis

	if otp.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	if otp.OtpCode != param.Otp {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP Salah",
		})
		return
	}

	// cek otp hanya unutk lupa sandi

	if otp.Type != "Forgot_password" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Diperuntukan untuk otp forgot password",
		})
		return
	}

	// cek otp sudah kadaluarsa belum

	if time.Now().After(otp.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "OTP sudah kadaluarsa",
			"note":          "Silahkan resend ulang!",
		})
		return
	}

	// cek otp sudah digunakan belum

	if otp.IsUsed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "sudah digunakan",
		})
		return
	}

	// set otp used
	_, err = h.UserUsecase.UseOtp(c.Request.Context(), param.Otp, uint64(otp.UserID))

	if err != nil {
		log.Logger.Info("Kesalahan server, h.UserUsecase.UseOtp, ", err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "berhasil",
		"note":    "Silahkan ganti password",
		"user_id": otp.UserID,
	})
}

func (h *UserHandler) ChangePassword(c *gin.Context) {

	var param models.NewPassword

	// cek valid kah parameternya
	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	// cek password sama confirm_password sama atau tidak
	if param.ConfirmPassword != param.Password {
		log.Logger.Info("Password tidak sama")
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Confirm password dan password tidak sama",
		})

		return
	}

	// belum cek tokennya
	// cek tokennya

	// if param.TokenPassword != "" {
	// 	return
	// }

	// ambil usernya terlebih dulu unutk testing
	user, err := h.UserUsecase.GetUserById(c.Request.Context(), param.UserID)

	if err != nil {
		log.Logger.Info(" h.UserUsecase.GetUserById error internal")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": err.Error(),
		})

		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error_message": "User tidak ditemukan",
		})
		return
	}

	_, err = h.UserUsecase.ChangePassword(
		c.Request.Context(),
		user.ID,
		user.Password,  // old hash
		param.Password, // new plain password
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id": "",
		"name":    user.Name,
		"email":   user.Email,
		"phone":   user.Phone,
		"message": "Berhasil mengganti password",
	})

}

func (h *UserHandler) LoginAdmin(c *gin.Context) {
	var param models.RequestLoginAdmin

	if err := c.ShouldBindJSON(&param); err != nil {
		log.Logger.Info("Invalid Parameter, ", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"error_message": "Invalid Parameter",
		})

		return
	}

	token, err := h.UserUsecase.LoginAdmin(c.Request.Context(), param)
	if err != nil {
		switch err.Error() {

		case "Username atau password salah":
			c.JSON(http.StatusBadRequest, gin.H{
				"error_message": err.Error(),
			})

		case "user tidak ditemukan", "user bukan admin":
			c.JSON(http.StatusNotFound, gin.H{
				"error_message": err.Error(),
			})

		default:
			log.Logger.Error("jasaHandler:  h.UserUsecase.LoginAdmin")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error_message": "internal server error",
			})
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login Admin Berhasil",
		"token":   token,
	})

}

func (h *UserHandler) GetAdminInfo(c *gin.Context) {

	role := c.GetString("role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error_message": "forbidden",
		})
		return
	}

	userID := c.GetInt64("user_id")

	admin, err := h.UserUsecase.GetUserById(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         admin.ID,
		"username":   admin.Username,
		"name":       admin.Name,
		"email":      admin.Email,
		"phone":      admin.Phone,
		"avatar_url": admin.AvatarURL,
	})
}

// Logout menghapus session user di server (user: hapus session; admin: tidak punya session, tetap 200)
func (h *UserHandler) Logout(c *gin.Context) {
	userIDAny, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_message": "unauthorized",
		})
		return
	}

	userID, ok := userIDAny.(int64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_message": "invalid token",
		})
		return
	}

	if err := h.UserUsecase.Logout(c.Request.Context(), userID); err != nil {
		log.Logger.Errorf("Logout error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error_message": "internal server error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout berhasil",
	})
}
