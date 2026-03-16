package bee

import (
	"github.com/zehongyang/bee/utils"
	"reflect"
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

type Person struct {
	Id   int64
	Name string
}

func TestDistinct(t *testing.T) {
	var arr = []int{1, 2, 3, 5, 1, 6, 8, 2}
	res := utils.Distinct(arr)
	t.Log(res)
	var persons = []Person{{Id: 1, Name: "zhangsan"}, {Id: 2, Name: "lisi"}, {Id: 3, Name: "wangwu"}, {Id: 1, Name: "zhangsan"}, {Id: 2, Name: "lisi"}}
	ress := utils.DistinctStruct(persons, func(t Person) int64 {
		return t.Id
	})
	t.Log(ress)
}

func TestPtr(t *testing.T) {
	var a *int
	t.Log(utils.Ptr(a))
	t.Log(utils.Value(a))
	var p *Person
	v := reflect.ValueOf(&p).Elem()
	if v.IsNil() {
		elem := reflect.New(v.Type().Elem())
		v.Set(elem)
	}
	idFiled := v.Elem().FieldByName("Id")
	idFiled.SetInt(10)
	t.Log(p)
}
