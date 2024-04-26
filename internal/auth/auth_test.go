package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		err     error
	}{
		{
			name:    "Valid Authorization Header",
			headers: http.Header{"Authorization": {"ApiKey my-api-key"}},
			want:    "my-api-key",
			err:     nil,
		},
		{
			name:    "No Authorization Header Included",
			headers: http.Header{},
			want:    "",
			err:     ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header - Missing Key",
			headers: http.Header{"Authorization": {"ApiKey"}},
			want:    "",
			err:     errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Authorization Header - Incorrect Type",
			headers: http.Header{"Authorization": {"Bearer token"}},
			want:    "",
			err:     errors.New("malformed authorization header"),
		},
		{
			name:    "Malformed Authorization Header - Empty Header",
			headers: http.Header{"Authorization": {""}},
			want:    "",
			err:     ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if err != nil && err.Error() != tt.err.Error() {
				t.Errorf("Got unexpected error: got %v, want %v", err, tt.err)
			}
			if got != tt.want {
				t.Errorf("Got %q, want %q", got, tt.want)
			}
		})
	}
}
