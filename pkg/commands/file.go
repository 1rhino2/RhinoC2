package commands

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type FileManager struct{}

func NewFileManager() *FileManager {
	return &FileManager{}
}

func validatePath(path string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}
	if len(path) > 4096 {
		return fmt.Errorf("path too long")
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal detected")
	}

	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}

	prohibited := []string{
		"\\Windows\\System32",
		"\\Windows\\SysWOW64",
		"/etc/shadow",
		"/etc/passwd",
		"/etc",
		"/boot",
		"/sys",
		"/proc",
	}

	for _, p := range prohibited {
		if strings.Contains(strings.ToLower(absPath), strings.ToLower(p)) {
			return fmt.Errorf("access to system directory prohibited")
		}
	}

	return nil
}

func (fm *FileManager) ReadFile(path string) ([]byte, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 104857600 {
		return nil, fmt.Errorf("file too large: max 100MB")
	}

	return os.ReadFile(path)
}

func (fm *FileManager) ReadFileBase64(path string) (string, error) {
	data, err := fm.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (fm *FileManager) WriteFile(path string, data []byte) error {
	if err := validatePath(path); err != nil {
		return err
	}
	if len(data) > 104857600 {
		return fmt.Errorf("data too large: max 100MB")
	}

	dir := filepath.Dir(path)
	if err := validatePath(dir); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (fm *FileManager) WriteFileBase64(path string, encodedData string) error {
	if len(encodedData) > 140000000 {
		return fmt.Errorf("encoded data too large")
	}

	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return fmt.Errorf("base64 decode failed: %v", err)
	}
	return fm.WriteFile(path, data)
}

func (fm *FileManager) DeleteFile(path string) error {
	if err := validatePath(path); err != nil {
		return err
	}
	return os.Remove(path)
}

func (fm *FileManager) ListDirectory(path string) ([]map[string]interface{}, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	if len(entries) > 10000 {
		entries = entries[:10000]
	}

	var result []map[string]interface{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		item := map[string]interface{}{
			"name":  entry.Name(),
			"isDir": entry.IsDir(),
			"size":  info.Size(),
			"mode":  info.Mode().String(),
		}
		result = append(result, item)
	}
	return result, nil
}

func (fm *FileManager) CreateDirectory(path string) error {
	if err := validatePath(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0755)
}

func (fm *FileManager) CopyFile(src, dst string) error {
	if err := validatePath(src); err != nil {
		return fmt.Errorf("invalid source: %v", err)
	}
	if err := validatePath(dst); err != nil {
		return fmt.Errorf("invalid destination: %v", err)
	}

	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.Size() > 104857600 {
		return fmt.Errorf("file too large: max 100MB")
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func (fm *FileManager) MoveFile(src, dst string) error {
	if err := validatePath(src); err != nil {
		return fmt.Errorf("invalid source: %v", err)
	}
	if err := validatePath(dst); err != nil {
		return fmt.Errorf("invalid destination: %v", err)
	}
	return os.Rename(src, dst)
}

func (fm *FileManager) GetFileInfo(path string) (map[string]interface{}, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"name":    info.Name(),
		"size":    info.Size(),
		"mode":    info.Mode().String(),
		"modTime": info.ModTime(),
		"isDir":   info.IsDir(),
	}, nil
}

func (fm *FileManager) SearchFiles(dir, pattern string) ([]string, error) {
	if err := validatePath(dir); err != nil {
		return nil, err
	}

	var matches []string
	count := 0
	maxResults := 1000

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if count >= maxResults {
			return filepath.SkipDir
		}

		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			return err
		}
		if matched {
			matches = append(matches, path)
			count++
		}
		return nil
	})
	return matches, err
}

func GetWorkingDirectory() (string, error) {
	return os.Getwd()
}

func ChangeDirectory(path string) error {
	if err := validatePath(path); err != nil {
		return err
	}
	return os.Chdir(path)
}

func GetTempDir() string {
	return os.TempDir()
}

func FileExists(path string) bool {
	if err := validatePath(path); err != nil {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func GetFileSize(path string) (int64, error) {
	if err := validatePath(path); err != nil {
		return 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
