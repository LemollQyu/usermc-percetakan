package config

type Config struct {
	App      AppConfig      `yaml:"app" validate:"required"`
	Database DatabaseConfig `yaml:"database" validate:"required"`
	Secret   SecretConfig   `yaml:"secret" validate:"required"`
	Email    EmailSecret    `yaml:"email" validate:"required"`
	Whatsapp WhatsappSecret `yaml:"whatsapp" validate:"required"`
	Google   GoogleSecret   `yaml:"google" validate:"required"`
}

type AppConfig struct {
	Port string `yaml:"port" validate:"required"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host" validate:"required"`
	User     string `yaml:"user" validate:"required"`
	Password string `yaml:"password" validate:"required"`
	Name     string `yaml:"name" validate:"required"`
	Port     string `yaml:"port" validate:"required"`
}

type SecretConfig struct {
	JWTSecret string `yaml:"jwt_secret" validate:"required"`
}

type EmailSecret struct {
	SmtpHost    string `yaml:"smtp_host" validate:"required"`
	SmtpPort    string `yaml:"smtp_port" validate:"required"`
	EmailHost   string `yaml:"email_host" validate:"required"`
	EmailSecret string `yaml:"email_secret" validate:"required"`
}

type WhatsappSecret struct {
	DeviceToken  string `yaml:"device_token" validate:"required"`
	AccountToken string `yaml:"account_token" validate:"required"`
}

type GoogleSecret struct {
	ClientId     string `yaml:"client_id" validate:"required"`
	ClientSecret string `yaml:"client_secret" validate:"required"`
}
