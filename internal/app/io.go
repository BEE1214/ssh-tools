package app

import "os"

// configReadFile reads the config file. Wrapped in a function so it can be
// overridden in tests if needed.
func configReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}