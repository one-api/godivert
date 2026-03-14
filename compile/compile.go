package compile

import (
	"fmt"

	"github.com/one-api/godivert/types"
)

// CompileFilter compiles a textual filter into an executable object.
// filter must be a non-empty string in textual format.
// Pre-compiled filter format (starting with '@') is not supported.
func CompileFilter(filter string, layer types.Layer) ([]types.Filter, error) {
	// Validate input
	if len(filter) == 0 {
		return nil, fmt.Errorf("empty filter")
	}

	// Check for pre-compiled filter object (not supported):
	if filter[0] == '@' {
		return nil, fmt.Errorf("not support yet")
	}

	// Tokenize the filter string:
	tokens, err := TokenizeFilter(filter, layer, uint(tokensSize-1))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	// Parse the filter into an expression:
	var i = 0
	expr, err := ParseFilter(tokens, &i, maxDepth, false)
	if err != nil {
		return nil, fmt.Errorf("parse filter: %w", err)
	}
	if i < (len(tokens)) && tokens[i].Kind != TokenEnd {
		return nil, fmt.Errorf("%w at %d", ErrUnexpectedToken, tokens[i].Pos)
	}

	// Flatten AST
	var ipEP = 0
	flattened, ipEP := FlattenExpr(expr, &ipEP, types.FilterResultAccept, types.FilterResultReject, nil)
	if ipEP < 0 {
		return nil, ErrTooLong
	}

	// Emit the final object.
	object := EmitFilter(flattened, ipEP)

	return object, nil
}
