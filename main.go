package main

import (
	"fmt"
	"net"
	"usermc/cmd/app/handler"
	"usermc/cmd/app/repository"
	"usermc/cmd/app/resource"
	"usermc/cmd/app/service"
	"usermc/cmd/app/usecase"
	"usermc/config"
	grpcUser "usermc/grpc"
	"usermc/infrastructure/log"
	"usermc/middleware"

	"usermc/proto/userpb"
	"usermc/routes"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

func main() {
	fmt.Println("Welcome api User management percetakan")

	cfg := config.LoadConfig()
	googleOAuth := config.NewGoogleOAuthConfig(cfg)

	fmt.Println("Config semua disni")
	fmt.Println("APP CONFIG:", cfg.App)
	fmt.Println("DATABASE CONFIG:", cfg.Database)
	fmt.Println("SECRET CONFIG:", cfg.Secret)
	fmt.Println("EMAIL CONFIG:", cfg.Email)
	fmt.Println("WHATSAPP CONFIG:", cfg.Whatsapp)
	fmt.Println("GOOGLE CONFIG:", cfg.Google)

	db := resource.InitDB(&cfg)
	log.SetupLogger()

	userRepostory := repository.NewUserRepository(db)
	userService := service.NewUserService(*userRepostory, cfg.Email, cfg.Whatsapp)
	userUsecase := usecase.NewUserUsecase(*userService, cfg.Secret.JWTSecret)
	userHandler := handler.NewUserHandler(*userUsecase, googleOAuth)

	port := cfg.App.Port

	router := gin.Default()
	router.Use(middleware.CORS([]string{"http://localhost:3000", "http://localhost:3001"}))
	routes.SetupRoutes(router, *userHandler, cfg.Secret.JWTSecret)

	// ---- HTTP SERVER ----
	go func() {
		log.Logger.Printf("HTTP server running on port : %s", port)
		if err := router.Run(":" + port); err != nil {
			log.Logger.Fatalf("HTTP server error: %v", err)
		}
	}()

	// ---- gRPC SERVER ----
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Logger.Fatalf("Failed to listen gRPC: %v", err)
	}

	grpcServer := grpc.NewServer()
	userpb.RegisterUserServiceServer(
		grpcServer,
		&grpcUser.GRPCServer{UserUsecase: *userUsecase},
	)

	for service, info := range grpcServer.GetServiceInfo() {
		log.Logger.Println("gRPC Service:", service)
		for _, method := range info.Methods {
			log.Logger.Println("  └─ Method:", method.Name)
		}
	}

	log.Logger.Println("gRPC server running on port :50051")

	if err := grpcServer.Serve(lis); err != nil {
		log.Logger.Fatalf("Failed to serve gRPC: %v", err)
	}

}
