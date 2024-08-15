package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/time_capsule/Auth-Servic-Health/config"
	_ "github.com/time_capsule/Auth-Servic-Health/docs"
	"github.com/time_capsule/Auth-Servic-Health/internal/db"
	"github.com/time_capsule/Auth-Servic-Health/internal/notifications"

	"github.com/time_capsule/Auth-Servic-Health/internal/redis"
	"github.com/time_capsule/Auth-Servic-Health/internal/user"
	v1 "github.com/time_capsule/Auth-Servic-Health/pkg/api/v1"
)

// @title           Swagger Example API
// @description     This is a sample server celler server.
// @termsOfService  http://swagger.io/terms/
// @securityDefinitions.apikey  ApiKeyAuth
// @in                          header
// @name                        Authorization
// @BasePath  /v1
// @description					Description for what is this security definition being used
func main() {
	cfg := config.Load()

	// Initialize database connection
	dbPool, err := db.Connect(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer dbPool.Close()

	// Initialize Redis client
	redisClient, err := redis.Connect(&cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer redisClient.Close()

	// Initialize user repository
	userRepo := user.NewUserRepo(dbPool)

	// Initialize notification service
	notificationService := notifications.NewNotificationService(&cfg, redisClient, userRepo)

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the notification worker
	notificationService.StartNotificationWorker(ctx)

	// Set up API routes
	router := v1.SetupRouter(dbPool, redisClient, &cfg)

	// Start the server in a goroutine
	go func() {
		if err := router.Run(cfg.HTTPPort); err != nil {
			log.Printf("Error starting server: %v", err)
			cancel()
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Cancel the context to stop the notification worker
	cancel()

	// Give the notification worker some time to finish its current task
	time.Sleep(2 * time.Second)

	log.Println("Server exiting")
}
