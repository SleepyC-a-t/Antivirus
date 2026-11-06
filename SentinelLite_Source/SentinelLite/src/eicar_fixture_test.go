package main

import "strings"

// Test-only representation. The distributed executable does not contain
// EICAR's entire test signature. This is used by the legacy Stage 3 tests.
var eicar = []byte(strings.Join([]string{
	"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
	"EICAR-STANDARD-",
	"ANTIVIRUS-TEST-FILE!$H+H*",
}, ""))
