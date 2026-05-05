package config

import "os"

type Config struct {
	CloudflareAccountID string
	CloudflareAPIToken  string
	R2BucketName        string
	ListenAddr          string
}

func Load() *Config {
	return &Config{
		CloudflareAccountID: os.Getenv("CLOUDFLARE_ACCOUNT_ID"),
		CloudflareAPIToken:  os.Getenv("CLOUDFLARE_API_TOKEN"),
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
