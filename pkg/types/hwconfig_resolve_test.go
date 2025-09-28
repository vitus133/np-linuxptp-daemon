package types

import (
	"testing"
)

func TestResolveClockAliases(t *testing.T) {
	// Create a test clock chain with aliases and various clock ID references
	clockChain := &ClockChain{
		CommonDefinitions: &CommonDefinitions{
			ClockIdentifiers: []ClockIdentifier{
				{
					Alias:   "TestLeader",
					ClockID: "0x507c6fffff1fb1b8",
				},
				{
					Alias:   "TestFollower",
					ClockID: "123456789",
				},
			},
		},
		Structure: []Subsystem{
			{
				Name: "TestSubsystem",
				DPLL: DPLL{
					ClockID: "TestLeader", // Should be resolved to alias value
				},
			},
		},
		Behavior: &Behavior{
			Sources: []SourceConfig{
				{
					Name:    "TestSource",
					ClockID: "TestFollower", // Should be resolved to alias value
				},
			},
			Conditions: []Condition{
				{
					Name: "TestCondition",
					DesiredStates: []DesiredState{
						{
							DPLL: &DPLLDesiredState{
								ClockID: "0xabcdef123456", // Direct clock ID
							},
						},
					},
				},
			},
		},
	}

	// Resolve clock aliases
	err := clockChain.ResolveClockAliases()
	if err != nil {
		t.Fatalf("ResolveClockAliases failed: %v", err)
	}

	// Verify clock identifiers were parsed
	if clockChain.CommonDefinitions.ClockIdentifiers[0].ClockIDParsed != 0x507c6fffff1fb1b8 {
		t.Errorf("Expected TestLeader parsed value 0x507c6fffff1fb1b8, got 0x%x",
			clockChain.CommonDefinitions.ClockIdentifiers[0].ClockIDParsed)
	}

	if clockChain.CommonDefinitions.ClockIdentifiers[1].ClockIDParsed != 123456789 {
		t.Errorf("Expected TestFollower parsed value 123456789, got %d",
			clockChain.CommonDefinitions.ClockIdentifiers[1].ClockIDParsed)
	}

	// Verify structure DPLL clock ID was resolved and parsed
	if clockChain.Structure[0].DPLL.ClockID != "0x507c6fffff1fb1b8" {
		t.Errorf("Expected structure DPLL ClockID to be resolved to '0x507c6fffff1fb1b8', got '%s'",
			clockChain.Structure[0].DPLL.ClockID)
	}

	if clockChain.Structure[0].DPLL.ClockIDParsed != 0x507c6fffff1fb1b8 {
		t.Errorf("Expected structure DPLL ClockIDParsed 0x507c6fffff1fb1b8, got 0x%x",
			clockChain.Structure[0].DPLL.ClockIDParsed)
	}

	// Verify source clock ID was resolved and parsed
	if clockChain.Behavior.Sources[0].ClockID != "123456789" {
		t.Errorf("Expected source ClockID to be resolved to '123456789', got '%s'",
			clockChain.Behavior.Sources[0].ClockID)
	}

	if clockChain.Behavior.Sources[0].ClockIDParsed != 123456789 {
		t.Errorf("Expected source ClockIDParsed 123456789, got %d",
			clockChain.Behavior.Sources[0].ClockIDParsed)
	}

	// Verify desired state clock ID was parsed (no alias resolution needed)
	expectedDirectValue := uint64(0xabcdef123456)
	if clockChain.Behavior.Conditions[0].DesiredStates[0].DPLL.ClockIDParsed != expectedDirectValue {
		t.Errorf("Expected desired state ClockIDParsed 0x%x, got 0x%x",
			expectedDirectValue, clockChain.Behavior.Conditions[0].DesiredStates[0].DPLL.ClockIDParsed)
	}

	t.Logf("✅ All clock aliases resolved and parsed successfully")
	t.Logf("   TestLeader: %s -> 0x%x",
		clockChain.CommonDefinitions.ClockIdentifiers[0].ClockID,
		clockChain.CommonDefinitions.ClockIdentifiers[0].ClockIDParsed)
	t.Logf("   TestFollower: %s -> %d",
		clockChain.CommonDefinitions.ClockIdentifiers[1].ClockID,
		clockChain.CommonDefinitions.ClockIdentifiers[1].ClockIDParsed)
}
