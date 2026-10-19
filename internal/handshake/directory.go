// Package handshake contains the NLS handshake entry points.
package handshake

import (
	"context"
	"errors"

	"github.com/TamilSelvam22112003/Nls-NetOS-v0.1.1/internal/directory"
)

// ResolvePeerForNewHandshake is the required directory authorization gate for
// every new handshake. It intentionally does not consult the cache as fallback.
func ResolvePeerForNewHandshake(ctx context.Context, cache *directory.Cache, routerID [16]byte) (directory.Record, error) {
	if cache == nil { return directory.Record{}, errors.New("directory cache and online CA lookup are required") }
	return cache.LookupForHandshake(ctx, routerID)
}
