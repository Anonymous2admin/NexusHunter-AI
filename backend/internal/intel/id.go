package intel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newID generates a random hex ID with a descriptive prefix.
func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}
