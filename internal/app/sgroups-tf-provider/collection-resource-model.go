package provider

type (

	// NamedResources -
	NamedResources[T SingleResource[T]] struct {
		Items map[string]T `tfsdk:"items"`
	}
)

// NewNamedResources -
func NewNamedResources[T SingleResource[T]]() (ret NamedResources[T]) {
	ret.Items = map[string]T{}
	return ret
}
