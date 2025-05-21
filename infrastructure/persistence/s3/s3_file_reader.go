package infrastructure

import (
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3FileReader struct {
	s3Client *s3.S3
	bucket   string
}

func NewS3FileReader() (*S3FileReader, error) {
	bucket := os.Getenv("S3_BUCKET_NAME")
	if bucket == "" {
		return nil, fmt.Errorf("S3_BUCKET_NAME environment variable is required")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating AWS session: %w", err)
	}

	return &S3FileReader{
		s3Client: s3.New(sess),
		bucket:   bucket,
	}, nil
}

func (s *S3FileReader) GetFileContent(key string) (io.ReadCloser, error) {
	resp, err := s.s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("error getting file from S3: %w", err)
	}
	return resp.Body, nil
}
