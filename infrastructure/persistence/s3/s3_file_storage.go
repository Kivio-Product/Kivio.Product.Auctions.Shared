package infrastructure

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3FileStorage struct {
	s3Client *s3.S3
	bucket   string
}

func NewS3FileStorage() (*S3FileStorage, error) {
	bucket := os.Getenv("S3_BUCKET_NAME")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session: %w", err)
	}

	return &S3FileStorage{
		s3Client: s3.New(sess),
		bucket:   bucket,
	}, nil
}

func (s *S3FileStorage) Upload(ctx context.Context, key string, content io.Reader) error {
	_, err := s.s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   aws.ReadSeekCloser(content),
	})
	if err != nil {
		return fmt.Errorf("error uploading file to S3: %w", err)
	}
	return nil
}

func (s *S3FileStorage) GetURL(ctx context.Context, key string, expiration time.Duration) (string, error) {
	req, _ := s.s3Client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})

	url, err := req.Presign(expiration)
	if err != nil {
		return "", fmt.Errorf("error generating presigned URL: %w", err)
	}
	return url, nil
}

func (s *S3FileStorage) Delete(ctx context.Context, key string) error {
	_, err := s.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("error deleting file from S3: %w", err)
	}
	return nil
}

func (s *S3FileStorage) ReadFile(ctx context.Context, key string) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	result, err := s.s3Client.GetObjectWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("error getting file from S3: %w", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", fmt.Errorf("error reading file from S3: %w", err)
	}

	return string(body), nil
}

func (s *S3FileStorage) ReadFileLines(ctx context.Context, key string) ([]string, error) {
	content, err := s.ReadFile(ctx, key)
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}

	return lines, nil
}
