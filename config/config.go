package config

import (
	"log"

	"github.com/spf13/viper"
)

func LoadConfig() Config {
	var cfg Config

	viper.SetConfigName("config")
	viper.SetConfigType("yml")
	viper.AddConfigPath("./files/config")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("error read config file: %v", err)
	}

	// Viper.Unmarshal kadang gagal untuk nested struct, jadi ambil manual:
	cfg.App.Port = viper.GetString("app.port")

	cfg.Database.Host = viper.GetString("database.host")
	cfg.Database.Port = viper.GetString("database.port")
	cfg.Database.User = viper.GetString("database.user")
	cfg.Database.Password = viper.GetString("database.password")
	cfg.Database.Name = viper.GetString("database.name")

	cfg.Secret.JWTSecret = viper.GetString("secret.jwt_secret")

	cfg.Email.SmtpHost = viper.GetString("email.smtp_host")
	cfg.Email.SmtpPort = viper.GetString("email.smtp_port")
	cfg.Email.EmailHost = viper.GetString("email.email_host")
	cfg.Email.EmailSecret = viper.GetString("email.email_secret")

	cfg.Whatsapp.DeviceToken = viper.GetString("whatsapp.device_token")
	cfg.Whatsapp.AccountToken = viper.GetString("whatsapp.account_token")

	cfg.Google.ClientId = viper.GetString("google.client_id")
	cfg.Google.ClientSecret = viper.GetString("google.client_secret")

	return cfg
}
