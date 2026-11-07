//go:build !windows

package main

import "errors"
type defenderJob struct{}
func newDefenderJob()(*defenderJob,error){return nil,errors.New("Windows Defender Job Object requires Windows")}
func (j *defenderJob)assign(pid int)error{return errors.New("not Windows")}
func (j *defenderJob)close(){}
