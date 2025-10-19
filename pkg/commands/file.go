package commands

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
)

type FileManager struct{}

func NewFileManager() *FileManager {
	return &FileManager{}
}

func (fm *FileManager) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (fm *FileManager) ReadFileBase64(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (fm *FileManager) WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (fm *FileManager) WriteFileBase64(path string, encodedData string) error {
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return err
	}
	return fm.WriteFile(path, data)
}

func (fm *FileManager) DeleteFile(path string) error {
	return os.Remove(path)
}

func (fm *FileManager) ListDirectory(path string) ([]map[string]interface{}, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
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
	return os.MkdirAll(path, 0755)
}

func (fm *FileManager) CopyFile(src, dst string) error {
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
	return os.Rename(src, dst)
}

func (fm *FileManager) GetFileInfo(path string) (map[string]interface{}, error) {
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
	var matches []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			return err
		}
		if matched {
			matches = append(matches, path)
		}
		return nil
	})
	return matches, err
}

func GetWorkingDirectory() (string, error) {
	return os.Getwd()
}

func ChangeDirectory(path string) error {
	return os.Chdir(path)
}

func GetTempDir() string {
	return os.TempDir()
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
