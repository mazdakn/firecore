package packet

type MetadataOption func(*Metadata)

type Metadata struct {
	IngressIface string
	EgressIface  string
	Name         string
}

func NewMetadata(opts ...MetadataOption) Metadata {
	var meta Metadata
	for _, o := range opts {
		o(&meta)
	}
	return meta
}
