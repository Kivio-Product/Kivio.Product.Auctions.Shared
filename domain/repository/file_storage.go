package domain

import (
	"context"
	"io"
	"time"
)

type FileStorage interface {
	Upload(ctx context.Context, key string, content io.Reader) error
	GetURL(ctx context.Context, key string, expiration time.Duration) (string, error)
	Delete(ctx context.Context, key string) error
	ReadFile(ctx context.Context, key string) (string, error)
	ReadFileLines(ctx context.Context, key string) ([]string, error)
}
