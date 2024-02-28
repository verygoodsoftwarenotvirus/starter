package types

import (
	"fmt"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var _ validation.Rule = (*stringDurationValidator)(nil)

type stringDurationValidator struct {
	maxDuration time.Duration
}

func (v *stringDurationValidator) Validate(value any) error {
	raw, ok := value.(string)
	if !ok {
		return errInvalidType
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}

	if d > v.maxDuration {
		return fmt.Errorf("duration too long: %s", d.String())
	}

	return nil
}
