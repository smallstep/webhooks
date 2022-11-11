module github.com/smallstep/webhooks

go 1.19

require (
	github.com/smallstep/certificates v0.21.0
	golang.org/x/crypto v0.0.0-20221005025214-4161e89ecf1b
)

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	go.step.sm/crypto v0.21.0 // indirect
	golang.org/x/net v0.0.0-20221012135044-0b7e1fb9d458 // indirect
	golang.org/x/sys v0.0.0-20221006211917-84dc82d7e875 // indirect
	golang.org/x/text v0.3.8 // indirect
)

replace github.com/smallstep/certificates => ../certificates

replace go.step.sm/linkedca => ../linkedca

replace go.step.sm/crypto => ../crypto
