package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/time_capsule/Auth-Servic-Health/config"
)

// Client represents a Redis client.
type Client struct {
	*redis.Client
}

// Connect establishes a connection to the Redis server.
func Connect(cfg *config.Config) (*Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddress,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Test the connection
	if _, err := client.Ping(context.Background()).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &Client{client}, nil
}

// SaveOTP saves the OTP code in Redis with an expiration time.
func (c *Client) SaveOTP(ctx context.Context, email string, otp string, expiration time.Duration) error {
	key := fmt.Sprintf("otp:%s", email)
	err := c.Set(ctx, key, otp, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to save OTP in Redis: %w", err)
	}
	return nil
}

// VerifyOTP verifies the OTP code against the one stored in Redis.
func (c *Client) VerifyOTP(ctx context.Context, email string, otp string) (bool, error) {
	key := fmt.Sprintf("otp:%s", email)
	storedOTP, err := c.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil // OTP not found (expired or never set)
		}
		return false, fmt.Errorf("failed to get OTP from Redis: %w", err)
	}
	return storedOTP == otp, nil
}

// Add these new methods for notification handling

type Notification struct {
	ID      string    `json:"id"`
	UserID  string    `json:"user_id"`
	Message string    `json:"message"`
	Created time.Time `json:"created"`
}

func (c *Client) AddNotification(ctx context.Context, notification Notification) error {
	json, err := json.Marshal(notification)
	if err != nil {
		return err
	}

	pipe := c.Pipeline()

	// Add to unread set
	pipe.SAdd(ctx, fmt.Sprintf("unread:%s", notification.UserID), notification.ID)

	// Add to sorted set for ordering
	pipe.ZAdd(ctx, fmt.Sprintf("notifications:%s", notification.UserID), &redis.Z{
		Score:  float64(notification.Created.Unix()),
		Member: notification.ID,
	})

	// Store notification data
	pipe.Set(ctx, fmt.Sprintf("notification:%s", notification.ID), json, 0)

	_, err = pipe.Exec(ctx)
	return err
}

func (c *Client) GetUnreadNotifications(ctx context.Context, userID string) ([]Notification, error) {
	// Get unread notification IDs
	unreadIDs, err := c.SMembers(ctx, fmt.Sprintf("unread:%s", userID)).Result()
	if err != nil {
		return nil, err
	}

	var notifications []Notification
	for _, id := range unreadIDs {
		notifJSON, err := c.Get(ctx, fmt.Sprintf("notification:%s", id)).Result()
		if err != nil {
			return nil, err
		}

		var notification Notification
		err = json.Unmarshal([]byte(notifJSON), &notification)
		if err != nil {
			return nil, err
		}
		notifications = append(notifications, notification)
	}

	return notifications, nil
}

func (c *Client) MarkNotificationAsRead(ctx context.Context, userID, notificationID string) error {
	pipe := c.Pipeline()

	// Remove from unread set
	pipe.SRem(ctx, fmt.Sprintf("unread:%s", userID), notificationID)

	// Add to read set
	pipe.SAdd(ctx, fmt.Sprintf("read:%s", userID), notificationID)

	_, err := pipe.Exec(ctx)
	return err
}
