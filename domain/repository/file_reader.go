package domain

import "io"

// FileReader defines the contract for reading file content from various sources
// 
// This interface abstracts file reading operations, providing a clean contract
// for implementations that handle reading files from different sources such as
// local filesystem, remote URLs, cloud storage, or other file systems.
//
// Implementations should handle:
//   - File content retrieval from various sources
//   - Proper resource management and cleanup
//   - Error handling for missing or inaccessible files
//   - Support for different file formats and encodings
//
type FileReader interface {
	// GetFileContent retrieves file content from the specified location
	// 
	// This method opens and reads a file from the given location, returning
	// an io.ReadCloser that allows streaming the file content. The caller
	// is responsible for closing the returned reader to free resources.
	//
	// Parameters:
	//   - location: Path, URL, or identifier of the file to read
	//
	// Returns:
	//   - io.ReadCloser: Reader for streaming file content
	//   - error: Returns error if file cannot be read
	//
	// Side Effects:
	//   - Opens file handle or network connection
	//   - Allocates resources for file reading
	//
	// Technical Details:
	//   - Caller must call Close() on returned reader
	//   - Location can be file path, URL, or storage key
	//   - Should handle different file systems transparently
	//   - Implementation should validate location format
	//   - Supports streaming for large files
	//   - Should handle network timeouts for remote files
	GetFileContent(location string) (io.ReadCloser, error)
}
