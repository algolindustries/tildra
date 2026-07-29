package memory_test

import (
	"testing"

	"github.com/tildra/tildra/server/internal/store"
	"github.com/tildra/tildra/server/internal/store/memory"
	"github.com/tildra/tildra/server/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s := memory.New()
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
