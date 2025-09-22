package bee

import (
	"github.com/zehongyang/bee/utils"
	"testing"
)

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()
	t.Log(sm)
	var mp = make(map[int64][]*Session)
	mp[1] = make([]*Session, 2)
	t.Log(mp[1])
	arr := mp[1]
	arr[0] = &Session{uid: 1}
	t.Log(mp[1])
}

func TestStack(t *testing.T) {
	t.Log(string(utils.Stack(1)))
}
