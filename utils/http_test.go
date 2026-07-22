package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type echoPayload struct {
	Name string `json:"name"`
}

// TestGetJSON 验证 GetJSON 能把普通结构体（非 proto.Message）作为响应体解析出来。
func TestGetJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(echoPayload{Name: "hello"})
	}))
	defer server.Close()

	var res echoPayload
	err := GetJSON(context.Background(), server.URL, &res)
	if err != nil {
		t.Fatalf("GetJSON returned error: %v", err)
	}
	if res.Name != "hello" {
		t.Fatalf("expected Name=hello, got %q", res.Name)
	}
}

// TestPostJSON 验证 PostJSON 能把普通结构体编码为请求体发送，并把响应体解析回普通结构体，全程不依赖 proto.Message。
func TestPostJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body echoPayload
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("server failed to decode request body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(echoPayload{Name: body.Name + "-ack"})
	}))
	defer server.Close()

	var res echoPayload
	err := PostJSON(context.Background(), server.URL, echoPayload{Name: "hi"}, &res, map[string]string{"X-Test": "1"})
	if err != nil {
		t.Fatalf("PostJSON returned error: %v", err)
	}
	if res.Name != "hi-ack" {
		t.Fatalf("expected Name=hi-ack, got %q", res.Name)
	}
}

// TestPostJSONNonOKStatus 验证非 200 状态码时返回明确的错误，而不是静默忽略。
func TestPostJSONNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	err := PostJSON(context.Background(), server.URL, nil, nil)
	if err == nil {
		t.Fatalf("expected error for non-200 status, got nil")
	}
}
