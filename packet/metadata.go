package packet

type MetadataOption func(*Metadata)

type Metadata struct {
	IngressIface string `yaml:"ingressIface,omitempty"`
	EgressIface  string `yaml:"egressIface,omitempty"`
	Name         string `yaml:"name,omitempty"`
}

func NewMetadata(opts ...MetadataOption) *Metadata {
	var meta Metadata
	for _, o := range opts {
		o(&meta)
	}
	return &meta
}
