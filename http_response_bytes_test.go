package bee

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestResponseBytesWritesRawBody 验证二进制响应把原始字节原样写回，并且 Code 头仍然是 200——
// 客户端判成败只看 Code 头，下载接口如果不设这个头，客户端会把成功的响应当成业务失败。
func TestResponseBytesWritesRawBody(t *testing.T) {
	payload := []byte{0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe} // 故意包含非法 UTF-8 字节
	server := NewHttpServer()
	server.Get("/download", func(ctx IContext) {
		ctx.ResponseBytes("application/pdf", "纪要.pdf", payload)
	})

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/download", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected http status 200, got %d", w.Code)
	}
	if got := w.Header().Get(HeaderCode); got != strconv.Itoa(http.StatusOK) {
		t.Fatalf("expected Code header 200, got %q", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/pdf" {
		t.Fatalf("expected content type application/pdf, got %q", got)
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Fatalf("body was not written verbatim: %v", w.Body.Bytes())
	}
}

// TestResponseBytesEncodesChineseFilename 验证中文文件名同时给出 ASCII 回退名和 UTF-8 编码名。
// 少了任何一个都会在某类客户端上表现为文件名乱码或整个丢失。
func TestResponseBytesEncodesChineseFilename(t *testing.T) {
	server := NewHttpServer()
	server.Get("/download", func(ctx IContext) {
		ctx.ResponseBytes("application/pdf", `周会"纪要.pdf`, []byte("x"))
	})

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/download", nil))

	disposition := w.Header().Get(HeaderContentDisposition)
	if !strings.HasPrefix(disposition, "attachment; ") {
		t.Fatalf("expected an attachment disposition, got %q", disposition)
	}
	// 中文和引号都必须从 ASCII 回退名里消失，否则引号会提前闭合 filename="..."。
	if !strings.Contains(disposition, `filename="___`) {
		t.Fatalf("expected non-ascii and quote chars replaced in the fallback name, got %q", disposition)
	}
	if !strings.Contains(disposition, "filename*=UTF-8''") {
		t.Fatalf("expected an RFC 5987 encoded filename, got %q", disposition)
	}
	if strings.Contains(disposition, "周会") {
		t.Fatalf("raw non-ascii bytes must not appear in the header, got %q", disposition)
	}
}

// TestResponseBytesDefaultsContentType 验证没指定类型时兜底成 octet-stream，
// 不指定类型时 gin 会写出 text/plain，客户端可能按文本解码而破坏二进制内容。
func TestResponseBytesDefaultsContentType(t *testing.T) {
	server := NewHttpServer()
	server.Get("/download", func(ctx IContext) {
		ctx.ResponseBytes("", "", []byte("x"))
	})

	w := httptest.NewRecorder()
	server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/download", nil))

	if got := w.Header().Get("Content-Type"); got != MIMEOctetStream {
		t.Fatalf("expected fallback content type %q, got %q", MIMEOctetStream, got)
	}
	if got := w.Header().Get(HeaderContentDisposition); got != "" {
		t.Fatalf("expected no disposition header when filename is empty, got %q", got)
	}
}
