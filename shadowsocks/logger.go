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
	fmt.Println(this.getCaller(5) + "=>")
	fmt.Println("  " + this.getCaller(4) + ":")
	return this.logger.WithFields((map[string]interface{})(this.fields))
}

func (this *LogType) setTab(args ...interface{}) []interface{} {
	args[0] = "\t" + args[0].(string)

	return args
}

func (this *LogType) Debug(args ...interface{}) (*LogType) {
	args = this.setTab(args)
	this.setFields().Debug(args...)

	return this
}

func (this *LogType) Info(args ...interface{}) (*LogType) {
	this.setFields().Info(args...)

	return this
}

func (this *LogType) Warn(args ...interface{}) (*LogType) {
	this.setFields().Warn(args...)

	return this
}

func (this *LogType) Error(args ...interface{}) (*LogType) {
	this.setFields().Error(args...)

	return this
}

func (this *LogType) Fatal(args ...interface{}) (*LogType) {
	this.setFields().Fatal(args...)

	return this
}

func (this *LogType) Fatalf(format string, args ...interface{}) (*LogType) {
	this.setFields().Fatalf(format, args...)

	return this
}

func (this *LogType) Panic(args ...interface{}) (*LogType) {
	this.setFields().Panic(args...)

	return this
}

func (this *LogType) Printf(format string, args ...interface{}) (*LogType) {
	this.setFields().Printf(format, args...)

	return this
}

func (this *LogType) Println(args ...interface{}) (*LogType) {
	this.setFields().Println(args...)

	return this
}

func (this *LogType) getCaller(skip int) string {
	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)

	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(skip, fpcs)
	if n == 0 {
		return "n/a" // proper error her would be better
	}

	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0]-1)
	if fun == nil {
		return "n/a"
	}

	return fun.Name()
}