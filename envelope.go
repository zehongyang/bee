package bee

// APIError 是统一响应体里携带的错误信息，用于告诉调用方出了什么问题、能不能重试。
type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// APIResponse 是所有 HTTP 接口统一使用的响应体结构：成功时 Data 有值、Error 为空；失败时相反。
type APIResponse struct {
	Data      any       `json:"data"`
	Error     *APIError `json:"error"`
	RequestID string    `json:"request_id"`
}

// NewAPIResponse 组装一个成功响应体，data 为空时业务方可以传 nil。
func NewAPIResponse(data any, requestID string) APIResponse {
	return APIResponse{Data: data, RequestID: requestID}
}

// NewAPIErrorResponse 组装一个失败响应体，code/message 面向客户端展示，retryable 告诉客户端是否值得重试。
func NewAPIErrorResponse(code, message string, retryable bool, requestID string) APIResponse {
	return APIResponse{
		Error:     &APIError{Code: code, Message: message, Retryable: retryable},
		RequestID: requestID,
	}
}

// RespondOK 按统一响应体格式返回成功结果，自动带上当前请求的 request_id（需要先注册 RequestID 中间件）。
func RespondOK(ctx IContext, data any) {
	ctx.ResponseOk(NewAPIResponse(data, GetRequestID(ctx)))
}

// RespondError 按统一响应体格式返回失败结果。
// 沿用 ResponseOk 走的响应通道（而不是 ResponseError），因为业务错误码和文案都要放进 JSON body，
// 由客户端统一解析 error 字段，不依赖传输层状态码。
func RespondError(ctx IContext, code, message string, retryable bool) {
	ctx.ResponseOk(NewAPIErrorResponse(code, message, retryable, GetRequestID(ctx)))
}
