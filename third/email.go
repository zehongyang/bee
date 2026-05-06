package third

type EmailOptionFunc func(option *EmailOption)

type EmailOption struct {
	host     string
	port     int
	username string
	password string
}

type EmailServer struct {
	cfg *EmailOption
}

func WithHost(host string) EmailOptionFunc {
	return func(opt *EmailOption) {
		opt.host = host
	}
}

func WithPort(port int) EmailOptionFunc {
	return func(opt *EmailOption) {
		opt.port = port
	}
}

func WithUsername(username string) EmailOptionFunc {
	return func(opt *EmailOption) {
		opt.username = username
	}
}

func WithPassword(password string) EmailOptionFunc {
	return func(opt *EmailOption) {
		opt.password = password
	}
}

func NewEmailServer(options ...EmailOptionFunc) *EmailServer {
	var opt EmailOption
	for _, option := range options {
		option(&opt)
	}
	return &EmailServer{cfg: &opt}
}
