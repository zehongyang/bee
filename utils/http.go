package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io"
	"net/http"
)

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
