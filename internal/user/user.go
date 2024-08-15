package user

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/time_capsule/Auth-Servic-Health/internal/models"
)

// UserRepo is the repository for interacting with user data.
type UserRepo struct {
	db *pgxpool.Pool
}

// NewUserRepo creates a new UserRepo.
func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{
		db: db,
	}
}

// CreateUser creates a new user in the database.
func (r *UserRepo) CreateUser(ctx context.Context, user *models.User) error {
	user.ID = uuid.New().String()
	query := `
		INSERT INTO users (id, username, email, password_hash, full_name, date_of_birth, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
	`

	_, err := r.db.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.DateOfBirth,
		user.Role,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUserByID retrieves a user by their ID.
func (r *UserRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, username, email, password_hash, full_name, date_of_birth, role, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.DateOfBirth,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by their email address.
func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, username, email, password_hash, full_name, date_of_birth, role, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.DateOfBirth,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// GetAllUsers retrieves all users from the database.
func (r *UserRepo) GetAllUsers(ctx context.Context) ([]*models.User, error) {
	var users []*models.User
	query := `
		SELECT id, username, email, password_hash, full_name, date_of_birth, role, created_at, updated_at
		FROM users
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.FullName,
			&user.DateOfBirth,
			&user.Role,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, &user)
	}

	return users, nil
}

// UpdateUser updates an existing user in the database.
func (r *UserRepo) UpdateUser(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET username = $1, email = $2, password_hash = $3, full_name = $4, date_of_birth = $5, role = $6, updated_at = NOW()
		WHERE id = $7
	`

	_, err := r.db.Exec(ctx, query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.DateOfBirth,
		user.Role,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// DeleteUser deletes a user from the database by their ID.
func (r *UserRepo) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	query := `
		DELETE FROM users
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// UserIDEmail represents a user's ID and email
type UserIDEmail struct {
	ID    uuid.UUID
	Email string
}

// GetAllUserIDsAndEmails retrieves all user IDs and emails from the database.
func (r *UserRepo) GetAllUserIDsAndEmails(ctx context.Context) ([]UserIDEmail, error) {
	var users []UserIDEmail
	query := `
        SELECT id, email
        FROM users
    `
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all user IDs and emails: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var user UserIDEmail
		if err := rows.Scan(&user.ID, &user.Email); err != nil {
			return nil, fmt.Errorf("failed to scan user ID and email: %w", err)
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user IDs and emails: %w", err)
	}

	return users, nil
}
