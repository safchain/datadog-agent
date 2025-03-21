// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package probe holds probe related files
package probe

import (
	"strconv"
	"strings"

	"github.com/DataDog/datadog-agent/comp/etw"
	etwimpl "github.com/DataDog/datadog-agent/comp/etw/impl"
)

const (
	idRegCreateKey     = uint16(1)  // regCreateKeyArgs
	idRegOpenKey       = uint16(2)  // CraeteKeyArgs
	idRegDeleteKey     = uint16(3)  // regDeleteKeyArgs
	idRegSetValueKey   = uint16(5)  // regSetValueKeyArgs
	idRegFlushKey      = uint16(12) // regDeleteKeyArgs
	idRegCloseKey      = uint16(13) // regDeleteKeyArgs
	idQuerySecurityKey = uint16(14) // regDeleteKeyArgs
	idSetSecurityKey   = uint16(15) // regDeleteKeyArgs

)

type regObjectPointer uint64

var (
	regprefix = `\REGISTRY`
)

/*
<template tid="task_0CreateKeyArgs">
      <data name="BaseObject" inType="win:Pointer"/>
      <data name="KeyObject" inType="win:Pointer"/>
      <data name="Status" inType="win:UInt32"/>
      <data name="Disposition" inType="win:UInt32"/>
      <data name="BaseName" inType="win:UnicodeString"/>
      <data name="RelativeName" inType="win:UnicodeString"/>
     </template>
*/

type regCreateKeyArgs struct {
	etw.DDEventHeader
	baseObject       regObjectPointer // pointer
	keyObject        regObjectPointer //pointer
	status           uint32
	disposition      uint32
	baseName         string
	relativeName     string
	computedFullPath string
}
type regOpenKeyArgs regCreateKeyArgs

/*
		<template tid="task_0DeleteKeyArgs">
	      <data name="KeyObject" inType="win:Pointer"/>
	      <data name="Status" inType="win:UInt32"/>
	      <data name="KeyName" inType="win:UnicodeString"/>
	     </template>
*/
type regDeleteKeyArgs struct {
	etw.DDEventHeader
	keyObject        regObjectPointer
	status           uint32
	keyName          string
	computedFullPath string
}
type regFlushKeyArgs regDeleteKeyArgs
type regCloseKeyArgs regDeleteKeyArgs
type regQuerySecurityKeyArgs regDeleteKeyArgs
type regSetSecurityKeyArgs regDeleteKeyArgs

/*
<template tid="task_0SetValueKeyArgs">

	<data name="KeyObject" inType="win:Pointer"/>
	<data name="Status" inType="win:UInt32"/>
	<data name="Type" inType="win:UInt32"/>
	<data name="DataSize" inType="win:UInt32"/>
	<data name="KeyName" inType="win:UnicodeString"/>
	<data name="ValueName" inType="win:UnicodeString"/>
	<data name="CapturedDataSize" inType="win:UInt16"/>
	<data name="CapturedData" inType="win:Binary" length="CapturedDataSize"/>
	<data name="PreviousDataType" inType="win:UInt32"/>
	<data name="PreviousDataSize" inType="win:UInt32"/>
	<data name="PreviousDataCapturedSize" inType="win:UInt16"/>
	<data name="PreviousData" inType="win:Binary" length="PreviousDataCapturedSize"/>

</template>
*/
type regSetValueKeyArgs struct {
	etw.DDEventHeader
	keyObject                regObjectPointer
	status                   uint32
	dataType                 uint32
	dataSize                 uint32
	keyName                  string
	valueName                string
	capturedDataSize         uint16
	capturedData             []byte
	previousDataType         uint32
	previousDataSize         uint32
	capturedPreviousDataSize uint16
	previousData             []byte
	computedFullPath         string
}

func (wp *WindowsProbe) parseRegCreateRegistryKey(e *etw.DDEventRecord) (*regCreateKeyArgs, error) {

	crc := &regCreateKeyArgs{
		DDEventHeader: e.EventHeader,
	}
	data := etwimpl.GetUserData(e)

	crc.baseObject = regObjectPointer(data.GetUint64(0))
	crc.keyObject = regObjectPointer(data.GetUint64(8))
	crc.status = data.GetUint32(16)
	crc.disposition = data.GetUint32(20)

	//var nextOffset int
	//var nulltermidx int
	var nextOffset int
	crc.baseName, nextOffset, _, _ = data.ParseUnicodeString(24)
	if nextOffset == -1 {
		nextOffset = 26
	}
	crc.relativeName, _, _, _ = data.ParseUnicodeString(nextOffset)

	wp.computeFullPath(crc)
	return crc, nil
}

func translateRegistryBasePath(s string) string {
	table := map[string]string{
		"\\\\REGISTRY\\MACHINE": "HKEY_LOCAL_MACHINE",
		"\\REGISTRY\\MACHINE":   "HKEY_LOCAL_MACHINE",
		"\\\\REGISTRY\\USER":    "HKEY_USERS",
		"\\REGISTRY\\USER":      "HKEY_USERS",
	}
	for k, v := range table {
		if strings.HasPrefix(strings.ToUpper(s), k) {
			s = v + s[len(k):]
		}
	}
	return s
}
func (cka *regCreateKeyArgs) translateBasePaths() {

	cka.relativeName = translateRegistryBasePath(cka.relativeName)

}
func (wp *WindowsProbe) parseRegOpenRegistryKey(e *etw.DDEventRecord) (*regOpenKeyArgs, error) {
	cka, err := wp.parseRegCreateRegistryKey(e)
	if err != nil {
		return nil, err
	}
	return (*regOpenKeyArgs)(cka), nil
}

func (wp *WindowsProbe) computeFullPath(cka *regCreateKeyArgs) {
	if strings.HasPrefix(cka.relativeName, regprefix) {
		cka.translateBasePaths()
		cka.computedFullPath = cka.relativeName
		if wp.regPathResolver.Add(cka.keyObject, cka.relativeName) {
			wp.stats.registryCacheEvictions++
		}
		return
	}
	if s, ok := wp.regPathResolver.Get(cka.keyObject); ok {
		cka.computedFullPath = s
	}
	var outstr string
	if cka.baseObject == 0 {
		if len(cka.baseName) > 0 {
			outstr = cka.baseName + "\\"
		}
		outstr += cka.relativeName
	} else {

		if s, ok := wp.regPathResolver.Get(cka.baseObject); ok {
			outstr = s + "\\" + cka.relativeName
		} else {
			outstr = cka.relativeName
		}
	}
	if wp.regPathResolver.Add(cka.keyObject, outstr) {
		wp.stats.registryCacheEvictions++
	}
	cka.computedFullPath = outstr

}
func (cka *regCreateKeyArgs) String() string {

	var output strings.Builder

	output.WriteString("PID: " + strconv.Itoa(int(cka.ProcessID)) + ", ")
	output.WriteString("Status: " + strconv.Itoa(int(cka.status)) + " Disposition: " + strconv.Itoa(int(cka.disposition)) + ", ")
	output.WriteString("BaseObject: " + strconv.FormatUint(uint64(cka.baseObject), 16) + ", ")
	output.WriteString("KeyObject: " + strconv.FormatUint(uint64(cka.keyObject), 16) + ", ")
	output.WriteString("Basename: " + cka.baseName + ", ")
	output.WriteString("Relativename: " + cka.relativeName + ", ")
	output.WriteString("Computedfullpath: " + cka.computedFullPath)
	return output.String()
}

func (cka *regOpenKeyArgs) String() string {
	return (*regCreateKeyArgs)(cka).String()
}

func (wp *WindowsProbe) parseRegDeleteRegistryKey(e *etw.DDEventRecord) (*regDeleteKeyArgs, error) {

	dka := &regDeleteKeyArgs{
		DDEventHeader: e.EventHeader,
	}

	data := etwimpl.GetUserData(e)

	dka.keyObject = regObjectPointer(data.GetUint64(0))
	dka.status = data.GetUint32(8)
	dka.keyName, _, _, _ = data.ParseUnicodeString(12)
	if s, ok := wp.regPathResolver.Get(dka.keyObject); ok {
		dka.computedFullPath = s
	}

	return dka, nil
}

func (wp *WindowsProbe) parseRegFlushKey(e *etw.DDEventRecord) (*regFlushKeyArgs, error) {
	dka, err := wp.parseRegDeleteRegistryKey(e)
	if err != nil {
		return nil, err
	}
	return (*regFlushKeyArgs)(dka), nil
}

func (wp *WindowsProbe) parseRegCloseKeyArgs(e *etw.DDEventRecord) (*regCloseKeyArgs, error) {
	dka, err := wp.parseRegDeleteRegistryKey(e)
	if err != nil {
		return nil, err
	}
	return (*regCloseKeyArgs)(dka), nil
}
func (wp *WindowsProbe) parseRegQuerySecurityKeyArgs(e *etw.DDEventRecord) (*regQuerySecurityKeyArgs, error) {
	dka, err := wp.parseRegDeleteRegistryKey(e)
	if err != nil {
		return nil, err
	}
	return (*regQuerySecurityKeyArgs)(dka), nil
}
func (wp *WindowsProbe) parseRegSetSecurityKeyArgs(e *etw.DDEventRecord) (*regSetSecurityKeyArgs, error) {
	dka, err := wp.parseRegDeleteRegistryKey(e)
	if err != nil {
		return nil, err
	}
	return (*regSetSecurityKeyArgs)(dka), nil
}

func (dka *regDeleteKeyArgs) String() string {
	var output strings.Builder

	output.WriteString("PID: " + strconv.Itoa(int(dka.ProcessID)) + ", ")
	output.WriteString("Status: " + strconv.Itoa(int(dka.status)) + ", ")
	output.WriteString("KeyName: " + dka.keyName + "\n")
	output.WriteString("Resolved path: " + dka.computedFullPath)

	//output.WriteString("  CapturedSize: " + strconv.Itoa(int(sv.capturedPreviousDataSize)) + " pvssize: " + strconv.Itoa(int(sv.previousDataSize)) + " capturedpvssize " + strconv.Itoa(int(sv.capturedPreviousDataSize)) + "\n")
	return output.String()

}

func (fka *regFlushKeyArgs) String() string {
	return (*regDeleteKeyArgs)(fka).String()
}
func (cka *regCloseKeyArgs) String() string {
	return (*regDeleteKeyArgs)(cka).String()
}

//nolint:unused
func (qka *regQuerySecurityKeyArgs) String() string {
	return (*regDeleteKeyArgs)(qka).String()
}

//nolint:unused
func (ska *regSetSecurityKeyArgs) String() string {
	return (*regDeleteKeyArgs)(ska).String()
}

func (wp *WindowsProbe) parseRegSetValueKey(e *etw.DDEventRecord) (*regSetValueKeyArgs, error) {

	sv := &regSetValueKeyArgs{
		DDEventHeader: e.EventHeader,
	}

	data := etwimpl.GetUserData(e)

	/*
		for i := 0; i < int(e.UserDataLength); i++ {
			fmt.Printf(" %2x", data[i])
			if (i+1)%16 == 0 {
				fmt.Printf("\n")
			}
		}
		fmt.Printf("\n")
	*/
	sv.keyObject = regObjectPointer(data.GetUint64(0))
	sv.status = data.GetUint32(8)
	sv.dataType = data.GetUint32(12)
	sv.dataSize = data.GetUint32(16)
	var nextOffset int
	var thisNextOffset int
	sv.keyName, nextOffset, _, _ = data.ParseUnicodeString(20)
	if nextOffset == -1 {
		nextOffset = 22
	}
	sv.valueName, thisNextOffset, _, _ = data.ParseUnicodeString(nextOffset)
	if thisNextOffset == -1 {
		nextOffset += 2
	} else {
		nextOffset = thisNextOffset
	}

	sv.capturedDataSize = data.GetUint16(nextOffset)
	nextOffset += 2

	// make a copy of the data because the underlying buffer here belongs to etw
	sv.capturedData = data.Bytes(nextOffset, int(sv.capturedDataSize))
	nextOffset += int(sv.capturedDataSize)

	sv.previousDataType = data.GetUint32(nextOffset)
	nextOffset += 4

	sv.previousDataSize = data.GetUint32(nextOffset)
	nextOffset += 4

	sv.capturedPreviousDataSize = data.GetUint16(nextOffset)
	nextOffset += 2

	sv.previousData = data.Bytes(nextOffset, int(sv.capturedPreviousDataSize))

	if s, ok := wp.regPathResolver.Get(sv.keyObject); ok {
		sv.computedFullPath = s
	}

	return sv, nil
}

func (sv *regSetValueKeyArgs) String() string {
	var output strings.Builder

	output.WriteString("PID: " + strconv.Itoa(int(sv.ProcessID)) + ", ")
	output.WriteString("Status: " + strconv.Itoa(int(sv.status)) + " dataType: " + strconv.Itoa(int(sv.dataType)) + " dataSize " + strconv.Itoa(int(sv.dataSize)) + ", ")
	output.WriteString("KeyObject: " + strconv.FormatUint(uint64(sv.keyObject), 16) + ", ")
	output.WriteString("KeyName: " + sv.keyName + ", ")
	output.WriteString("CalueName: " + sv.valueName + ", ")
	output.WriteString("Computed path: " + sv.computedFullPath)

	//output.WriteString("  CapturedSize: " + strconv.Itoa(int(sv.capturedPreviousDataSize)) + " pvssize: " + strconv.Itoa(int(sv.previousDataSize)) + " capturedpvssize " + strconv.Itoa(int(sv.capturedPreviousDataSize)) + "\n")
	return output.String()

}
