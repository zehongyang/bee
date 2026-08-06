package bee

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetRawBodyKeepsBodyBindable 验证 GetRawBody 取走原文之后 Bind 仍然拿得到数据。
//
// 这是第三方 Webhook 处理的固定套路：先用原始字节验签，再把内容解析成结构体。
// http.Request.Body 是一次性的流，如果 GetRawBody 读完不把它塞回去，第二步就会拿到空对象——
// 表现是验签通过但订单号为空，非常难查，所以用测试把这个行为钉住。
func TestGetRawBodyKeepsBodyBindable(t *testing.T) {
	const payload = `{"order_no":"MP20260806001","amount_cents":1200}`

	server := NewHttpServer()
	var (
		raw   string
		bound struct {
			OrderNo     string `json:"order_no"`
			AmountCents int64  `json:"amount_cents"`
		}
		bindErr error
	)
	server.Post("/webhook", func(ctx IContext) {
		data, err := ctx.GetRawBody()
		if err != nil {
			t.Errorf("GetRawBody failed: %v", err)
		}
		raw = string(data)
		bindErr = ctx.Bind(&bound)
		ctx.ResponseOk(nil)
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	server.engine.ServeHTTP(httptest.NewRecorder(), req)

	if raw != payload {
		t.Fatalf("expected raw body to be byte-identical to the request, got %q", raw)
	}
	if bindErr != nil {
		t.Fatalf("expected Bind to still work after GetRawBody, got error: %v", bindErr)
	}
	if bound.OrderNo != "MP20260806001" || bound.AmountCents != 1200 {
		t.Fatalf("expected Bind to see the replayed body, got %+v", bound)
	}
}

// TestGetRawBodyOnEmptyBody 验证没有请求体时返回空而不是报错，
// 免得 handler 为了一个 GET 请求还要额外判空。
func TestGetRawBodyOnEmptyBody(t *testing.T) {
	server := NewHttpServer()
	var (
		data []byte
		err  error
	)
	server.Get("/empty", func(ctx IContext) {
		data, err = ctx.GetRawBody()
		ctx.ResponseOk(nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/empty", nil)
	server.engine.ServeHTTP(httptest.NewRecorder(), req)

	if err != nil {
		t.Fatalf("expected no error for an empty body, got %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("expected empty raw body, got %q", data)
	}
}
