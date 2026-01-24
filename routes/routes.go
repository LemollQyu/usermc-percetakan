package routes

import (
	"usermc/cmd/app/handler"
	"usermc/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine, userHandler handler.UserHandler, jwtSecret string) {
	// cek request logging
	router.Use(middleware.RequestLogger())

	router.GET("/ping", userHandler.Ping)
	// router.GET("/coba-get", userHandler.CobaGet)
	// router.POST("/coba-post", userHandler.CobaPost)
	groupV1 := router.Group("/api/v1")

	// PUBLIC ROUTES
	// auth google
	router.GET("/auth/google", userHandler.GoogleAuth)
	router.GET("/auth/google/callback", userHandler.GoogleAuthCallback)

	groupV1.POST("/register", userHandler.Register)
	groupV1.POST("/verify-email", userHandler.VerifyEmail) // resend otp email
	groupV1.POST("/verify-otp-email", userHandler.VerifyOTPEmail)
	groupV1.POST("/verify-phone", userHandler.VerifyPhone) //resend otp whatsapp
	groupV1.POST("/verify-otp-phone", userHandler.VerifyOTPPhone)

	groupV1.POST("/forgot-password", userHandler.ForgotPassword) // resend otp lupa password
	groupV1.POST("/verify-otp-forgot-password", userHandler.VerifyOTPForgotPassword)
	// change password forgot password
	groupV1.POST("/change-password", userHandler.ChangePassword)

	groupV1.POST("/login", userHandler.Login)

	// login admin

	groupV1.POST("/admin-login", userHandler.LoginAdmin)

	authMiddleware := middleware.AuthMiddleware(jwtSecret)

	private := router.Group("/api/v1/i")
	private.Use(authMiddleware)

	// user biasa
	private.GET("/user-info", userHandler.GetUserInfo)

	// admin only
	admin := private.Group("/admin")
	admin.Use(middleware.AdminOnly())
	admin.GET("/info", userHandler.GetAdminInfo)

}
