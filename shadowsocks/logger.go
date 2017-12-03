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
	//this.fields = fields
	this.setFields(fields)
	return this
}

func (this *LogType) setFields(fields LogFields) {
	file, line, fun := this.getCallerInfo(6)
	fmt.Printf("\nLine: %d %s %s =>\n", line, fun, file)

	file, line, fun = this.getCallerInfo(5)
	fmt.Printf("  Line: %d %s %s =>\n", line, fun, file)

	file, line, fun = this.getCallerInfo(4)
	fmt.Printf("    Line: %d %s %s =>\n", line, fun, file)

	//fields := this.fields
	//this.fields = nil
	//return this.logger.WithFields((map[string]interface{})(fields))
	this.fields = this.logger.WithFields((map[string]interface{})(fields))
}

func (this *LogType) Debug(args ...interface{}) (*LogType) {
	//this.setFields().Debug(args...)
	if this.fields != nil {
		this.fields.Debug(args...)
		this.fields = nil
	} else { this.logger.Debug(args...) }

	return this
}

func (this *LogType) Debugf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Debugf(format, args...)
	if this.fields != nil {
		this.fields.Debugf(format, args...)
		this.fields = nil
	} else { this.logger.Debugf(format, args...) }

	return this
}

func (this *LogType) Info(args ...interface{}) (*LogType) {
	//this.setFields().Info(args...)
	if this.fields != nil {
		this.fields.Info(args...)
		this.fields = nil
	} else { this.logger.Info(args...) }

	return this
}

func (this *LogType) Infof(format string, args ...interface{}) (*LogType) {
	//this.setFields().Infof(format, args...)
	if this.fields != nil {
		this.fields.Infof(format, args...)
		this.fields = nil
	} else { this.logger.Infof(format, args...) }

	return this
}

func (this *LogType) Warn(args ...interface{}) (*LogType) {
	//this.setFields().Warn(args...)
	if this.fields != nil {
		this.fields.Warn(args...)
		this.fields = nil
	} else { this.logger.Warn(args...) }

	return this
}

func (this *LogType) Warnf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Warnf(format, args...)
	if this.fields != nil {
		this.fields.Warnf(format, args...)
		this.fields = nil
	} else { this.logger.Warnf(format, args...) }

	return this
}

func (this *LogType) Error(args ...interface{}) (*LogType) {
	//this.setFields().Error(args...)
	if this.fields != nil {
		this.fields.Error(args...)
		this.fields = nil
	} else { this.logger.Error(args...) }

	return this
}

func (this *LogType) Errorf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Errorf(format, args...)
	if this.fields != nil {
		this.fields.Errorf(format, args...)
		this.fields = nil
	} else { this.logger.Errorf(format, args...) }

	return this
}

func (this *LogType) Fatal(args ...interface{}) (*LogType) {
	//this.setFields().Fatal(args...)
	if this.fields != nil {
		this.fields.Fatal(args...)
		this.fields = nil
	} else { this.logger.Fatal(args...) }

	return this
}

func (this *LogType) Fatalf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Fatalf(format, args...)
	if this.fields != nil {
		this.fields.Fatalf(format, args...)
		this.fields = nil
	} else { this.logger.Fatalf(format, args...) }

	return this
}

func (this *LogType) Panic(args ...interface{}) (*LogType) {
	//this.setFields().Panic(args...)
	if this.fields != nil {
		this.fields.Panic(args...)
		this.fields = nil
	} else { this.logger.Panic(args...) }

	return this
}

func (this *LogType) Panicf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Panicf(format, args...)
	if this.fields != nil {
		this.fields.Panicf(format, args...)
		this.fields = nil
	} else { this.logger.Panicf(format, args...) }

	return this
}

func (this *LogType) Printf(format string, args ...interface{}) (*LogType) {
	//this.setFields().Printf(format, args...)
	if this.fields != nil {
		this.fields.Printf(format, args...)
		this.fields = nil
	} else { this.logger.Printf(format, args...) }

	return this
}

func (this *LogType) Println(args ...interface{}) (*LogType) {
	//this.setFields().Println(args...)
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