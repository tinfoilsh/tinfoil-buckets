package config

import "os"

type Config struct {
	CloudflareAccountID string
	R2AccessKeyID       string
	R2SecretAccessKey   string
	R2BucketName        string
	ListenAddr          string
}

func Load() *Config {
	return &Config{
		CloudflareAccountID: os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		R2AccessKeyID:       os.Getenv("R2_TINFOIL_BUCKET_ACCESS_KEY_ID"),
		R2SecretAccessKey:   os.Getenv("R2_TINFOIL_BUCKET_SECRET_ACCESS_KEY"),
		R2BucketName:        getEnv("R2_BUCKET_NAME", "tinfoil-bucket"),
		ListenAddr:          getEnv("LISTEN_ADDR", ":8089"),
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
