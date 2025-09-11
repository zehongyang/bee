package bee

import (
	"testing"
)

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()
	t.Log(sm)
	var mp = make(map[int64][2]*Session)
	t.Log(mp[1])
}
