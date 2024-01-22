package cdn

type OnResult func(string)

type Options struct {
	DnsOerverFile string
	OnResult OnResult
}
