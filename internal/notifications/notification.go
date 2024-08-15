package notifications

import (
	"context"
	"fmt"
	"time"

	"github.com/time_capsule/Auth-Servic-Health/config"
	"github.com/time_capsule/Auth-Servic-Health/internal/email"
	"github.com/time_capsule/Auth-Servic-Health/internal/redis"
	"github.com/time_capsule/Auth-Servic-Health/internal/user"
)

type NotificationService struct {
	cfg         *config.Config
	redisClient *redis.Client
	userRepo    *user.UserRepo
}

func NewNotificationService(cfg *config.Config, redisClient *redis.Client, userRepo *user.UserRepo) *NotificationService {
	return &NotificationService{
		cfg:         cfg,
		redisClient: redisClient,
		userRepo:    userRepo,
	}
}

func (s *NotificationService) StartNotificationWorker(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				s.processNotifications(ctx)
				time.Sleep(1 * time.Second) // Wait for 1 second before the next iteration
			}
		}
	}()
}

func (s *NotificationService) processNotifications(ctx context.Context) {
	// Get all user IDs and emails in one query
	users, err := s.userRepo.GetAllUserIDsAndEmails(ctx)
	if err != nil {
		fmt.Printf("Error getting user IDs and emails: %v\n", err)
		return
	}

	for _, user := range users {
		notifications, err := s.redisClient.GetUnreadNotifications(ctx, user.ID.String())
		if err != nil {
			fmt.Printf("Error getting unread notifications for user %s: %v\n", user.ID, err)
			continue
		}

		for _, notification := range notifications {
			err = s.sendNotificationEmail(user.Email, notification.Message)
			if err != nil {
				fmt.Printf("Error sending notification email to user %s: %v\n", user.ID, err)
				continue
			}

			err = s.redisClient.MarkNotificationAsRead(ctx, user.ID.String(), notification.ID)
			if err != nil {
				fmt.Printf("Error marking notification as read for user %s: %v\n", user.ID, err)
			}
		}
	}
}

func (s *NotificationService) sendNotificationEmail(recipient, message string) error {
	subject := "New Notification"
	body := fmt.Sprintf("You have a new notification: %s", message)
	emailMessage := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

	return email.SendEmail(s.cfg, recipient, emailMessage)
}
