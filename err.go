package bee

import "errors"

var (
	ErrUnSupportVersion = errors.New("unSupport version")
	ErrPackageLength    = errors.New("package length error")
	ErrContentType      = errors.New("content type error")
	ErrProtoObj         = errors.New("proto obj error")
)
