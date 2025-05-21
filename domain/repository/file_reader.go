package domain

import "io"

type FileReader interface {
	GetFileContent(location string) (io.ReadCloser, error)
}
