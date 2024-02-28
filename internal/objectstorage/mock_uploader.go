package objectstorage

import (
	"context"
	"net/http"

	"github.com/stretchr/testify/mock"
)

type (
	// MockUploader is a mock uploads.UploadManager.
	MockUploader struct {
		mock.Mock
	}
)

// SaveFile is a mock function.
func (m *MockUploader) SaveFile(ctx context.Context, path string, content []byte) error {
	return m.Called(ctx, path, content).Error(0)
}

// ReadFile is a mock function.
func (m *MockUploader) ReadFile(ctx context.Context, path string) ([]byte, error) {
	returnValues := m.Called(ctx, path)

	return returnValues.Get(0).([]byte), returnValues.Error(1)
}

// ServeFiles is a mock function.
func (m *MockUploader) ServeFiles(res http.ResponseWriter, req *http.Request) {
	m.Called(res, req)
}
