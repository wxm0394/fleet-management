package store

import (
	"time"

	"github.com/google/uuid"
)

// SeedFreeResources populates the free_resources table with initial demo data
// if and only if the table is currently empty. This makes the panel useful out
// of the box without duplicating rows on every server restart.
func (s *Store) SeedFreeResources() error {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM free_resources`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // already seeded
	}

	id1, err := uuid.NewV7()
	if err != nil {
		return err
	}
	id2, err := uuid.NewV7()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	freeResources := []FreeResourceRecord{
		{
			ID:        id1.String(),
			Name:      "GPU Cloud",
			Category:  "Cloud",
			Status:    "active",
			ExpiresAt: time.Now().AddDate(0, 0, 30).Unix(),
			Quota:     "1000",
			Note:      "Free GPU cloud resources",
			Link:      "https://example.com/gpu-cloud",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        id2.String(),
			Name:      "Storage Cloud",
			Category:  "Cloud",
			Status:    "active",
			ExpiresAt: time.Now().AddDate(0, 0, 60).Unix(),
			Quota:     "500",
			Note:      "Free storage cloud resources",
			Link:      "https://example.com/storage-cloud",
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	for _, resource := range freeResources {
		_, err := s.db.Exec(
			`INSERT INTO free_resources (id, name, category, status, expires_at, quota, note, link, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			resource.ID, resource.Name, resource.Category, resource.Status, resource.ExpiresAt, resource.Quota, resource.Note, resource.Link, resource.CreatedAt, resource.UpdatedAt,
		)
		if err != nil {
			return err
		}
	}
	return nil
}
