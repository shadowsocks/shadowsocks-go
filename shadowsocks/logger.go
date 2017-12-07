package shadowsocks

import (
	"github.com/sirupsen/logrus"
	"runtime"
	"fmt"
	"os"
)

type LogType struct {
	logger *logrus.Logger
	fields *logrus.Entry
}

const caller_level = 6
const stack_len = 3

type LogFields map[string]interface{}

func New() (*LogType) {
	logger := logrus.New()
	logger.Out = os.Stdout
	logger.Formatter = &TextFormatter{}
	return &LogType{
		logger,
		nil,
	}
}

var Logger = New()

func (this *LogType) Fields(fields LogFields) (*LogType) { this.setFields(fields); return this }
func (this *LogType) formatOutput(skip int) {
	for i := 0; i < stack_len; i++ {
		file, line, fun := this.getCallerInfo(skip-i)
		if i == 0 {
			fmt.Print("\n")
		}
		for j := 0; j < i; j++ {
			fmt.Print(" ")
		}
		fmt.Printf("Line: %d %s %s =>\n", line, fun, file)
	}
}
func (this *LogType) setFields(fields LogFields) {
	//file, line, fun := this.getCallerInfo(6)
	//fmt.Printf("\nLine: %d %s %s =>\n", line, fun, file)
	//
	//file, line, fun = this.getCallerInfo(5)
	//fmt.Printf("  Line: %d %s %s =>\n", line, fun, file)
	//
	//file, line, fun = this.getCallerInfo(4)
	//fmt.Printf("    Line: %d %s %s =>\n", line, fun, file)

	this.fields = this.logger.WithFields((map[string]interface{})(fields))
}

func (this *LogType) Debug(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Debug(args...)
		this.fields = nil
	} else { this.logger.Debug(args...) }

	return this
}

func (this *LogType) Debugf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Debugf(format, args...)
		this.fields = nil
	} else { this.logger.Debugf(format, args...) }

	return this
}

func (this *LogType) Info(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Info(args...)
		this.fields = nil
	} else { this.logger.Info(args...) }

	return this
}

func (this *LogType) Infof(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Infof(format, args...)
		this.fields = nil
	} else { this.logger.Infof(format, args...) }

	return this
}

func (this *LogType) Warn(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Warn(args...)
		this.fields = nil
	} else { this.logger.Warn(args...) }

	return this
}

func (this *LogType) Warnf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Warnf(format, args...)
		this.fields = nil
	} else { this.logger.Warnf(format, args...) }

	return this
}

func (this *LogType) Error(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Error(args...)
		this.fields = nil
	} else { this.logger.Error(args...) }

	return this
}

func (this *LogType) Errorf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Errorf(format, args...)
		this.fields = nil
	} else { this.logger.Errorf(format, args...) }

	return this
}

func (this *LogType) Fatal(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Fatal(args...)
		this.fields = nil
	} else { this.logger.Fatal(args...) }

	return this
}

func (this *LogType) Fatalf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Fatalf(format, args...)
		this.fields = nil
	} else { this.logger.Fatalf(format, args...) }

	return this
}

func (this *LogType) Panic(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Panic(args...)
		this.fields = nil
	} else { this.logger.Panic(args...) }

	return this
}

func (this *LogType) Panicf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Panicf(format, args...)
		this.fields = nil
	} else { this.logger.Panicf(format, args...) }

	return this
}

func (this *LogType) Printf(format string, args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Printf(format, args...)
		this.fields = nil
	} else { this.logger.Printf(format, args...) }

	return this
}

func (this *LogType) Println(args ...interface{}) (*LogType) {
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Println(args...)
		this.fields = nil
	} else { this.logger.Println(args...) }

	return this
}

func (this *LogType) getCallerInfo(skip int) (file string, line int, fun_name string) {
	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)
	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(skip, fpcs); if n == 0 { fun_name = "n/a"; return }
	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0]-1); if fun == nil { fun_name = "n/a"; return }
	fun_name = fun.Name(); file, line = fun.FileLine(fpcs[0]-1); return
}