package types

import (
	"testing"
)

func TestParseClockID(t *testing.T) {
	tests := []struct {
		name        string
		clockID     string
		expected    uint64
		expectError bool
	}{
		{
			name:        "Valid hexadecimal with 0x prefix",
			clockID:     "0x507c6fffff5c4ae8",
			expected:    0x507c6fffff5c4ae8,
			expectError: false,
		},
		{
			name:        "Valid hexadecimal with 0X prefix",
			clockID:     "0X507C6FFFFF5C4AE8",
			expected:    0x507c6fffff5c4ae8,
			expectError: false,
		},
		{
			name:        "Valid decimal",
			clockID:     "5789604461865584360",
			expected:    5789604461865584360,
			expectError: false,
		},
		{
			name:        "Valid small decimal",
			clockID:     "123",
			expected:    123,
			expectError: false,
		},
		{
			name:        "Valid small hexadecimal",
			clockID:     "0xff",
			expected:    255,
			expectError: false,
		},
		{
			name:        "Empty string",
			clockID:     "",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Invalid format - no prefix hex",
			clockID:     "507c6fffff5c4ae8",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Invalid format - invalid hex characters",
			clockID:     "0xGHIJ",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Invalid format - negative decimal",
			clockID:     "-123",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Invalid format - mixed characters",
			clockID:     "123abc",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Invalid format - float",
			clockID:     "123.456",
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseClockID(tc.clockID)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for clock ID '%s', but got none", tc.clockID)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for clock ID '%s': %v", tc.clockID, err)
				} else if result != tc.expected {
					t.Errorf("Expected %d for clock ID '%s', got %d", tc.expected, tc.clockID, result)
				}
			}
		})
	}
}

func TestParseClockIDSafe(t *testing.T) {
	tests := []struct {
		name           string
		clockID        string
		expectedValue  uint64
		expectedString string
		expectError    bool
	}{
		{
			name:           "Valid hexadecimal",
			clockID:        "0x507c6fffff5c4ae8",
			expectedValue:  0x507c6fffff5c4ae8,
			expectedString: "0x507c6fffff5c4ae8",
			expectError:    false,
		},
		{
			name:           "Valid decimal",
			clockID:        "123456789",
			expectedValue:  123456789,
			expectedString: "123456789",
			expectError:    false,
		},
		{
			name:           "Empty string",
			clockID:        "",
			expectedValue:  0,
			expectedString: "",
			expectError:    true,
		},
		{
			name:           "Invalid format",
			clockID:        "invalid",
			expectedValue:  0,
			expectedString: "",
			expectError:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, str, err := ParseClockIDSafe(tc.clockID)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for clock ID '%s', but got none", tc.clockID)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for clock ID '%s': %v", tc.clockID, err)
				} else {
					if value != tc.expectedValue {
						t.Errorf("Expected value %d for clock ID '%s', got %d", tc.expectedValue, tc.clockID, value)
					}
					if str != tc.expectedString {
						t.Errorf("Expected string '%s' for clock ID '%s', got '%s'", tc.expectedString, tc.clockID, str)
					}
				}
			}
		})
	}
}

func TestValidateClockID(t *testing.T) {
	tests := []struct {
		name        string
		clockID     string
		expectError bool
	}{
		{
			name:        "Valid hexadecimal",
			clockID:     "0x507c6fffff5c4ae8",
			expectError: false,
		},
		{
			name:        "Valid decimal",
			clockID:     "123456789",
			expectError: false,
		},
		{
			name:        "Invalid format - no prefix hex",
			clockID:     "507c6fffff5c4ae8",
			expectError: true,
		},
		{
			name:        "Invalid format - mixed",
			clockID:     "123abc",
			expectError: true,
		},
		{
			name:        "Empty string",
			clockID:     "",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClockID(tc.clockID)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for clock ID '%s', but got none", tc.clockID)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for clock ID '%s': %v", tc.clockID, err)
				}
			}
		})
	}
}
