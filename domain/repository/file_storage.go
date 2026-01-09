package domain

import (
	"context"
	"io"
	"time"
)

// FileStorage defines the contract for file storage operations
// 
// This interface abstracts file storage operations, providing a clean contract
// for implementations that handle file uploads, downloads, URL generation, and
// file management operations. It supports various storage backends like S3,
// local filesystem, or other cloud storage solutions.
//
// Implementations should handle:
//   - File uploads with content streaming
//   - Secure URL generation with expiration
//   - File deletion operations
//   - File content reading
//   - Line-by-line file reading
//
type FileStorage interface {
	// Upload stores a file in the storage system using the provided key and content
	// 
	// This method stores file content in the storage system using the specified key.
	// The content is read from the provided io.Reader, allowing for efficient
	// streaming of large files without loading them entirely into memory.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout management
	//   - key: Unique identifier/path for the file in storage
	//   - content: Reader containing the file content to upload
	//
	// Returns:
	//   - error: Returns error if upload fails
	//
	// Side Effects:
	//   - Creates new file in storage system
	//   - Consumes content from the provided reader
	//
	// Technical Details:
	//   - Uses io.Reader for memory-efficient streaming
	//   - Key should be unique to avoid overwrites
	//   - Implementation should handle network timeouts
	//   - Content is read until EOF or error occurs
	Upload(ctx context.Context, key string, content io.Reader) error

	// GetURL generates a secure, time-limited URL for accessing a stored file
	// 
	// This method creates a pre-signed URL that allows temporary access to a
	// stored file. The URL expires after the specified duration, providing
	// security for sensitive file access.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout management
	//   - key: Unique identifier/path of the file in storage
	//   - expiration: Duration after which the URL becomes invalid
	//
	// Returns:
	//   - string: Pre-signed URL for file access
	//   - error: Returns error if URL generation fails
	//
	// Side Effects:
	//   - None (pure function)
	//
	// Technical Details:
	//   - URL expires after specified duration
	//   - Should include authentication tokens
	//   - Implementation should validate file exists
	//   - URL should be HTTPS for security
	GetURL(ctx context.Context, key string, expiration time.Duration) (string, error)

	// Delete removes a file from the storage system
	// 
	// This method permanently removes a file from the storage system using
	// its unique key. The operation is irreversible and should be used
	// with caution.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout management
	//   - key: Unique identifier/path of the file to delete
	//
	// Returns:
	//   - error: Returns error if deletion fails
	//
	// Side Effects:
	//   - Permanently removes file from storage
	//   - File becomes inaccessible immediately
	//
	// Technical Details:
	//   - Hard delete operation (no soft delete)
	//   - Should handle non-existent files gracefully
	//   - Implementation should validate permissions
	//   - No recovery possible after deletion
	Delete(ctx context.Context, key string) error

	// ReadFile retrieves the complete content of a stored file as a string
	// 
	// This method reads the entire content of a file and returns it as a
	// string. It's suitable for text files or small binary files that can
	// be safely loaded into memory.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout management
	//   - key: Unique identifier/path of the file to read
	//
	// Returns:
	//   - string: Complete file content as string
	//   - error: Returns error if read fails
	//
	// Side Effects:
	//   - Loads entire file content into memory
	//
	// Technical Details:
	//   - Suitable for text files and small files
	//   - Entire file content loaded into memory
	//   - Should handle encoding properly
	//   - Not recommended for large files
	ReadFile(ctx context.Context, key string) (string, error)

	// ReadFileLines retrieves the content of a file as an array of lines
	// 
	// This method reads a file and splits its content into individual lines,
	// returning them as a slice of strings. It's particularly useful for
	// processing text files line by line.
	//
	// Parameters:
	//   - ctx: Context for request cancellation and timeout management
	//   - key: Unique identifier/path of the file to read
	//
	// Returns:
	//   - []string: Array of file lines
	//   - error: Returns error if read fails
	//
	// Side Effects:
	//   - Loads entire file content into memory
	//
	// Technical Details:
	//   - Splits content by newline characters
	//   - Handles different line ending formats
	//   - Returns empty slice for empty files
	//   - Each line is a separate string element
	ReadFileLines(ctx context.Context, key string) ([]string, error)
}
