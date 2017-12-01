package shadowsocks

import (
	"github.com/sirupsen/logrus"
	"runtime"
	"fmt"
	"os"
)

type LogType struct {
	logger *logrus.Logger
	fields LogFields
}

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

func (this *LogType) Fields(fields LogFields) (*LogType) {
	this.fields = fields

	return this
}

func (this *LogType) setFields() *logrus.Entry {
	file, line, fun := this.getCallerInfo(5)
	fmt.Printf("\nLine: %d %s %s =>\n", line, fun, file)

	file, line, fun = this.getCallerInfo(4)
	fmt.Printf("  Line: %d %s %s =>\n", line, fun, file)

	fields := this.fields
	this.fields = nil
	return this.logger.WithFields((map[string]interface{})(fields))
}

func (this *LogType) Debug(args ...interface{}) (*LogType) {
	this.setFields().Debug(args...)
	this.fields = nil

	return this
}

func (this *LogType) Debugf(format string, args ...interface{}) (*LogType) {
	this.setFields().Debugf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Info(args ...interface{}) (*LogType) {
	this.setFields().Info(args...)
	this.fields = nil

	return this
}

func (this *LogType) Infof(format string, args ...interface{}) (*LogType) {
	this.setFields().Infof(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Warn(args ...interface{}) (*LogType) {
	this.setFields().Warn(args...)
	this.fields = nil

	return this
}

func (this *LogType) Warnf(format string, args ...interface{}) (*LogType) {
	this.setFields().Warnf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Error(args ...interface{}) (*LogType) {
	this.setFields().Error(args...)
	this.fields = nil

	return this
}

func (this *LogType) Errorf(format string, args ...interface{}) (*LogType) {
	this.setFields().Errorf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Fatal(args ...interface{}) (*LogType) {
	this.setFields().Fatal(args...)
	this.fields = nil

	return this
}

func (this *LogType) Fatalf(format string, args ...interface{}) (*LogType) {
	this.setFields().Fatalf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Panic(args ...interface{}) (*LogType) {
	this.setFields().Panic(args...)
	this.fields = nil

	return this
}

func (this *LogType) Panicf(format string, args ...interface{}) (*LogType) {
	this.setFields().Panicf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Printf(format string, args ...interface{}) (*LogType) {
	this.setFields().Printf(format, args...)
	this.fields = nil

	return this
}

func (this *LogType) Println(args ...interface{}) (*LogType) {
	this.setFields().Println(args...)
	this.fields = nil

	return this
}

func (this *LogType) getCallerInfo(skip int) (file string, line int, fun_name string) {
	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)

	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(skip, fpcs)
	if n == 0 {
		fun_name = "n/a"
		return
	}

	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0]-1)
	if fun == nil {
		fun_name = "n/a"
		return
	}

	fun_name = fun.Name()

	file, line = fun.FileLine(fpcs[0]-1)

	return
}