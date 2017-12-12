package shadowsocks

import (
	"github.com/sirupsen/logrus"
	"runtime"
	"fmt"
	"os"
	"reflect"
)

type LogType struct {
	logger *logrus.Logger
	fields *logrus.Entry
}

const caller_level = 6
const stack_len = 3
const debug_level = logrus.DebugLevel
const begin_len = 64
const last_len = 64
var middle_bytes = []byte{0, 0, 0}

type LogFields map[string]interface{}

func New() (*LogType) {
	logger := logrus.New()
	//logger.Out = os.Stdout
	logger.Formatter = &TextFormatter{}
	logger.SetLevel(debug_level)

	loggerInst := new(LogType)
	loggerInst.logger = logger

	return loggerInst
}

var Logger = New()

func (this *LogType) SetOutput(output *os.File) {
	this.logger.Out = output
}

func (this *LogType) Fields(fields LogFields) (*LogType) {
	for index, item := range fields {
		item_type := reflect.TypeOf(item).String()
		if item_type == "[]uint8" {
			item_len := len(item.([]uint8))
			if item_len > begin_len+last_len {
				new_item := make([]byte, begin_len+len(middle_bytes)+last_len)
				copy(new_item, item.([]uint8)[:begin_len])
				copy(new_item[begin_len:], middle_bytes)
				copy(new_item[begin_len+len(middle_bytes):], item.([]uint8)[item_len-last_len:])
				item = new_item
				fields[index] = item
			}
		} else if item_type == "string" {
			item_len := len(item.(string))
			if item_len > begin_len+last_len {
				new_item := make([]byte, begin_len+len(middle_bytes)+last_len)
				copy(new_item, item.(string)[:begin_len])
				copy(new_item[begin_len:], middle_bytes)
				copy(new_item[begin_len+len(middle_bytes):], item.(string)[item_len-last_len:])
				item = string(new_item)
				fields[index] = item
			}
		}
	}
	this.setFields(fields)
	return this
}
func (this *LogType) formatOutput(skip int) {
	if !DebugLog {
		return
	}
	for i := 0; i < stack_len; i++ {
		file, line, fun := this.getCallerInfo(skip - i)
		for j := 0; j < i; j++ {
			fmt.Print(" ")
		}
		fmt.Printf("Line: %d %s %s =>\n", line, fun, file)
	}
}

func (this *LogType) setFields(fields LogFields) {
	this.fields = this.logger.WithFields((map[string]interface{})(fields))
}

func (this *LogType) Debug(args ...interface{}) (*LogType) {
	if debug_level < logrus.DebugLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Debug(args...)
		this.fields = nil
	} else {
		this.logger.Debug(args...)
	}

	return this
}

func (this *LogType) Debugf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.DebugLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Debugf(format, args...)
		this.fields = nil
	} else {
		this.logger.Debugf(format, args...)
	}

	return this
}

func (this *LogType) Info(args ...interface{}) (*LogType) {
	if debug_level < logrus.InfoLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Info(args...)
		this.fields = nil
	} else {
		this.logger.Info(args...)
	}

	return this
}

func (this *LogType) Infof(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.InfoLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Infof(format, args...)
		this.fields = nil
	} else {
		this.logger.Infof(format, args...)
	}

	return this
}

func (this *LogType) Warn(args ...interface{}) (*LogType) {
	if debug_level < logrus.WarnLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Warn(args...)
		this.fields = nil
	} else {
		this.logger.Warn(args...)
	}

	return this
}

func (this *LogType) Warnf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.WarnLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Warnf(format, args...)
		this.fields = nil
	} else {
		this.logger.Warnf(format, args...)
	}

	return this
}

func (this *LogType) Error(args ...interface{}) (*LogType) {
	if debug_level < logrus.ErrorLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Error(args...)
		this.fields = nil
	} else {
		this.logger.Error(args...)
	}

	return this
}

func (this *LogType) Errorf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.ErrorLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Errorf(format, args...)
		this.fields = nil
	} else {
		this.logger.Errorf(format, args...)
	}

	return this
}

func (this *LogType) Fatal(args ...interface{}) (*LogType) {
	if debug_level < logrus.FatalLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Fatal(args...)
		this.fields = nil
	} else {
		this.logger.Fatal(args...)
	}

	return this
}

func (this *LogType) Fatalf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.FatalLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Fatalf(format, args...)
		this.fields = nil
	} else {
		this.logger.Fatalf(format, args...)
	}

	return this
}

func (this *LogType) Panic(args ...interface{}) (*LogType) {
	if debug_level < logrus.PanicLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Panic(args...)
		this.fields = nil
	} else {
		this.logger.Panic(args...)
	}

	return this
}

func (this *LogType) Panicf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.PanicLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Panicf(format, args...)
		this.fields = nil
	} else {
		this.logger.Panicf(format, args...)
	}

	return this
}

func (this *LogType) Printf(format string, args ...interface{}) (*LogType) {
	if debug_level < logrus.InfoLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Printf(format, args...)
		this.fields = nil
	} else {
		this.logger.Printf(format, args...)
	}

	return this
}

func (this *LogType) Println(args ...interface{}) (*LogType) {
	if debug_level < logrus.InfoLevel {
		return this
	}
	this.formatOutput(caller_level)
	if this.fields != nil {
		this.fields.Println(args...)
		this.fields = nil
	} else {
		this.logger.Println(args...)
	}

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
	fun := runtime.FuncForPC(fpcs[0] - 1)
	if fun == nil {
		fun_name = "n/a"
		return
	}
	fun_name = fun.Name()
	file, line = fun.FileLine(fpcs[0] - 1)
	return
}
