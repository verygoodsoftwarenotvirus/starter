package types

import (
	"github.com/jinzhu/copier"
)

var copyOpt = copier.Option{
	IgnoreEmpty: true,
	DeepCopy:    true,
	Converters:  []copier.TypeConverter{
		//
	},
}

// Merge will copy fields from the second variable into the first.
func Merge(into, from any) error {
	return copier.CopyWithOption(into, from, copyOpt)
}
