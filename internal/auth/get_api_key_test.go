package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header      http.Header
		key         string
		expectError bool
		errMsg      string
	}{
		"valid API Key": {
			header:      http.Header{"Authorization": []string{"ApiKey 1"}},
			key:         "1",
			expectError: false,
			errMsg:      "",
		},
		"header without key": {
			header:      http.Header{"Authorization": []string{"ApiKey"}},
			key:         "",
			expectError: true,
			errMsg:      "malformed authorization header",
		},
		"wrong header": {
			header:      http.Header{"noname": []string{"ApiKey 1"}},
			key:         "",
			expectError: true,
			errMsg:      ErrNoAuthHeaderIncluded.Error(),
		},
		"wrong auth scheme": {
			header:      http.Header{"Authorization": []string{"Bearer xxxxxx"}},
			key:         "",
			expectError: true,
			errMsg:      "malformed authorization header",
		},
		"empty auth scheme": {
			header:      http.Header{"Authorization": []string{""}},
			key:         "",
			expectError: true,
			errMsg:      ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.header)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error: %v, got: nill", tc.errMsg)
				}
				if err.Error() != tc.errMsg {
					t.Fatalf("expected error: %v, got: %v", tc.errMsg, err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotKey != tc.key {
				t.Fatalf("expected key: %v, got: %v", tc.key, gotKey)
			}
		})

	}

}
