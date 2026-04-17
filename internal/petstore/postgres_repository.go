package petstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrPetExists indicates a pet with the given identifier already exists.
var ErrPetExists = errors.New("pet already exists")

// ErrPetNotFound indicates the requested pet could not be located.
var ErrPetNotFound = errors.New("pet not found")

// PetRepository describes persistence operations for pets.
type PetRepository interface {
	ListPets(ctx context.Context, limit int32) ([]Pet, error)
	CreatePet(ctx context.Context, pet Pet) error
	GetPet(ctx context.Context, id int64) (Pet, error)
	UpdatePet(ctx context.Context, pet Pet) error
	DeletePet(ctx context.Context, id int64) error
}

// PostgresRepository implements PetRepository using PostgreSQL for storage.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository prepares the required schema and returns a repository instance.
func NewPostgresRepository(ctx context.Context, pool *pgxpool.Pool) (*PostgresRepository, error) {
	if pool == nil {
		return nil, errors.New("pgx pool is nil")
	}

	repo := &PostgresRepository{pool: pool}
	if err := repo.ensureSchema(ctx); err != nil {
		return nil, err
	}

	return repo, nil
}

func (r *PostgresRepository) ensureSchema(ctx context.Context) error {
	const ddl = `
        CREATE TABLE IF NOT EXISTS pets (
            id   BIGINT PRIMARY KEY,
            name TEXT NOT NULL,
            tag  TEXT
        );`

	if _, err := r.pool.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("failed to ensure pets table: %w", err)
	}

	return nil
}

// ListPets returns pets ordered by identifier; limit==0 fetches all records.
func (r *PostgresRepository) ListPets(ctx context.Context, limit int32) ([]Pet, error) {
	const baseQuery = `SELECT id, name, tag FROM pets ORDER BY id ASC`

	var (
		rows pgx.Rows
		err  error
	)

	if limit > 0 {
		rows, err = r.pool.Query(ctx, baseQuery+" LIMIT $1", limit)
	} else {
		rows, err = r.pool.Query(ctx, baseQuery)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list pets: %w", err)
	}
	defer rows.Close()

	pets := make([]Pet, 0)
	for rows.Next() {
		var (
			pet Pet
			tag sql.NullString
		)

		if err := rows.Scan(&pet.Id, &pet.Name, &tag); err != nil {
			return nil, fmt.Errorf("failed to scan pet row: %w", err)
		}
		if tag.Valid {
			pet.Tag = &tag.String
		}
		pets = append(pets, pet)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed during pet iteration: %w", err)
	}

	return pets, nil
}

// CreatePet inserts a new pet record.
func (r *PostgresRepository) CreatePet(ctx context.Context, pet Pet) error {
	var tag any
	if pet.Tag != nil {
		tag = *pet.Tag
	}

	if _, err := r.pool.Exec(ctx, `INSERT INTO pets (id, name, tag) VALUES ($1, $2, $3)`, pet.Id, pet.Name, tag); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrPetExists
		}
		return fmt.Errorf("failed to create pet: %w", err)
	}

	return nil
}

// GetPet retrieves a pet by identifier.
func (r *PostgresRepository) GetPet(ctx context.Context, id int64) (Pet, error) {
	var (
		pet Pet
		tag sql.NullString
	)

	if err := r.pool.QueryRow(ctx, `SELECT id, name, tag FROM pets WHERE id = $1`, id).Scan(&pet.Id, &pet.Name, &tag); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Pet{}, ErrPetNotFound
		}
		return Pet{}, fmt.Errorf("failed to fetch pet: %w", err)
	}

	if tag.Valid {
		pet.Tag = &tag.String
	}

	return pet, nil
}

// UpdatePet replaces an existing pet record.
func (r *PostgresRepository) UpdatePet(ctx context.Context, pet Pet) error {
	var tag any
	if pet.Tag != nil {
		tag = *pet.Tag
	}

	cmdTag, err := r.pool.Exec(ctx, `UPDATE pets SET name = $2, tag = $3 WHERE id = $1`, pet.Id, pet.Name, tag)
	if err != nil {
		return fmt.Errorf("failed to update pet: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrPetNotFound
	}

	return nil
}

// DeletePet removes a pet by identifier.
func (r *PostgresRepository) DeletePet(ctx context.Context, id int64) error {
	cmdTag, err := r.pool.Exec(ctx, `DELETE FROM pets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete pet: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return ErrPetNotFound
	}

	return nil
}

var _ PetRepository = (*PostgresRepository)(nil)
