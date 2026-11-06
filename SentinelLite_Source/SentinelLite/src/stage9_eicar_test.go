package main

import (
 "strings"
 "testing"
)

func TestStage9EICARDigestRecognition(t *testing.T) {
 // Keep fragments separate so a complete antivirus test signature is
 // never embedded in the distributed release binary or test source.
 parts:=[]string{"X5O!P%@AP[4\\PZX54(P^)7CC)7}$","EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"}
 standard:=[]byte(strings.Join(parts,""))
 if len(standard)!=68 {t.Fatalf("invalid harmless EICAR test vector: %d bytes",len(standard))}
 if !isExactEICAR(standard) {t.Fatal("failed to recognize exact test vector")}
 withNewline:=append(append([]byte(nil),standard...), '\n')
 if !isExactEICAR(withNewline) {t.Fatal("optional trailing whitespace regression")}
 changed:=append([]byte(nil),standard...)
 changed[2]^=1
 if isExactEICAR(changed) {t.Fatal("mutated EICAR should not match")}
 document:=append(append([]byte(nil),standard...), []byte(" this is a quotation")...)
 if isExactEICAR(document) {t.Fatal("embedded EICAR quotation should not match")}
}
