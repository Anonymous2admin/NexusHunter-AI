package storage

import (
	"encoding/json"
	"fmt"
)

// safeUnmarshal safely decodes non-empty JSON data into target v, returning an explicit storage error on corruption.
func safeUnmarshal(data []byte, v interface{}, contextName string) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("storage JSON corruption in %s: %w", contextName, err)
	}
	return nil
}
