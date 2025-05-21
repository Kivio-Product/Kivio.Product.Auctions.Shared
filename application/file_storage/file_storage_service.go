package application

import (
	"context"
	"fmt"
	"io"
	"time"

	domain "github.com/Kivio-Product/Kivio.Product.Auctions.Shared/domain/repository"
)

type FileStorageService struct {
	fileStorage domain.FileStorage
}

func NewFileStorageService(fileStorage domain.FileStorage) *FileStorageService {
	return &FileStorageService{
		fileStorage: fileStorage,
	}
}

func (s *FileStorageService) UploadFile(ctx context.Context, key string, content io.Reader) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	return s.fileStorage.Upload(ctx, key, content)
}

func (s *FileStorageService) GetFileURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}
	if expiration <= 0 {
		return "", fmt.Errorf("expiration must be greater than 0")
	}
	return s.fileStorage.GetURL(ctx, key, expiration)
}

func (s *FileStorageService) DeleteFile(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	return s.fileStorage.Delete(ctx, key)
}

func (s *FileStorageService) ReadFile(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}
	return s.fileStorage.ReadFile(ctx, key)
}

func (s *FileStorageService) ReadFileLines(ctx context.Context, key string) ([]string, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}
	return s.fileStorage.ReadFileLines(ctx, key)
}
