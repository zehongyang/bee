package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
)

// Get 发起一个 GET 请求，把响应体按 JSON 解析进 res；res 必须是 proto.Message，用于对接走 protobuf 的内部服务。
func Get(url string, res proto.Message) error {
	if url == "" {
		return errors.New("url is empty")
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	if res != nil {
		var buf bytes.Buffer
		io.Copy(&buf, resp.Body)
		resp.Body.Close()
		err = json.Unmarshal(buf.Bytes(), res)
		if err != nil {
			return err
		}
	}
	return nil
}

// PostJson 发起一个 POST 请求，把 q 编码成 JSON 发送，再把响应体按 JSON 解析进 res；q/res 必须是 proto.Message。
func PostJson(url string, q, res proto.Message, header ...map[string]string) error {
	if url == "" {
		return errors.New("url is empty")
	}
	var buf bytes.Buffer
	if q != nil {
		marshal, err := json.Marshal(q)
		if err != nil {
			return err
		}
		buf.Write(marshal)
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(header) > 0 {
		for k, v := range header[0] {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	if res != nil {
		var buf bytes.Buffer
		io.Copy(&buf, resp.Body)
		resp.Body.Close()
		err = json.Unmarshal(buf.Bytes(), res)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetJSON 发起一个 GET 请求，把响应体按 JSON 解析进 res；res 可以是任意结构体指针，不要求实现 proto.Message，
// 用于对接 DeepSeek、微信支付、支付宝这类标准 JSON API。ctx 用于控制请求超时和取消。
func GetJSON(ctx context.Context, url string, res any, header ...map[string]string) error {
	if url == "" {
		return errors.New("url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if len(header) > 0 {
		for k, v := range header[0] {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	if res != nil {
		return json.NewDecoder(resp.Body).Decode(res)
	}
	return nil
}

// PostJSON 发起一个 POST 请求，把 body 编码成 JSON 发送，再把响应体按 JSON 解析进 res；
// body/res 可以是任意结构体指针，不要求实现 proto.Message，用于对接 DeepSeek、微信支付、支付宝这类标准 JSON API。
// ctx 用于控制请求超时和取消。
func PostJSON(ctx context.Context, url string, body, res any, header ...map[string]string) error {
	if url == "" {
		return errors.New("url is empty")
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(header) > 0 {
		for k, v := range header[0] {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code %d", resp.StatusCode)
	}
	if res != nil {
		return json.NewDecoder(resp.Body).Decode(res)
	}
	return nil
}
