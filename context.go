package bee

const (
	HeaderCode     = "Code"
	HeaderError    = "Error"
	AccountInfoKey = "Account"
)

type AccountInfo struct {
	Uid int
}

type Handler func(ctx IContext)

type IContext interface {
	Bind(obj any) error
	GetAccount() AccountInfo
	ResponseOk(obj any)
	ResponseError(code int, msg ...string)
	Next()
	AbortWithStatus(code int)
	SetAccount(account AccountInfo)
	GetHeader(key string) string
	SetHeader(key, value string)
	BindHeader(obj any) error
	BindUri(obj any) error
}
