package main

import (
	"fmt"
	"errors"
)

type AminalInfo struct {
	atype string
	KeySize    int
	IVSize     int
	New func(atype string) (Aminal, error)
}

var info = map[string]*AminalInfo{
	"pug":   {"pug", 16, 16, newDog(newPug)},
	//"husky":   {"husky", 24, 16, newDog},
	//"boxer":   {"boxer", 32, 16, newDog},
	"parrot":   {"parrot", 16, 16, newParrot},
	//"raven":   {"raven", 24, 16, newBird},
	//"dove":   {"dove", 32, 16, newBird},
}

type Aminal interface {
	setName(name string)
	getName() string
}

type Dog interface {
	Aminal
	Run()
}

type Bird interface {
	Aminal
	Fly()
}

func CheckAminal(aminal string) error {
	if aminal == "" {
		aminal = "pug"
	}
	_, ok := info[aminal]
	if !ok {
		return errors.New("Unsupported aminal: " + aminal)
	}
	return nil
}

func newAminal(atype string) (a Aminal, err error) {
	mi, ok := info[atype]
	if !ok {
		err = errors.New("Unsupported encryption aminal: " + atype)
		return
	}

	return mi.New(atype)
}

//////////////////////////////////////////
//////////////////////////////////////////
func newDog() (Aminal, error) {
	return new(Dog), nil
}

//////////////////////////////////////////
//////////////////////////////////////////
func newBird() (Aminal, error) {
	return new(Bird), nil
}
//////////////////////////////////////////
//////////////////////////////////////////
type Parrot struct {
	Bird
	name string
}

func (this *Parrot) setName(name string) {
	this.name = name
}

func (this *Parrot) getName() string {
	return this.name
}

func (this *Parrot) Fly() {
	fmt.Print("I can fly\n")
}

func newParrot() Bird {
	return new(Parrot)
}
//////////////////////////////////////////
//////////////////////////////////////////
type Pug struct {
	Dog
	name string
}

func (this *Pug) setName(name string) {
	this.name = name
}

func (this *Pug) getName() string {
	return this.name
}

func (this *Pug) Run() {
	fmt.Print("I can run\n")
}

func newPug() (Dog, error) {
	return new(Pug), nil
}
//////////////////////////////////////////
//////////////////////////////////////////

//func getAnimalName(animal Aminal) {
//	fmt.Print(animal.getName())
//}

func main() {
	aminal, err := newAminal("parrot")
	if err != nil {
		fmt.Print(err)
	}

	fmt.Print(aminal)
	//pug := newAminal("pug")
	//pug.setName("wolf")
	//pug.
	//
	//getAnimalName(dog)
	//
	//cat := newAminal("cat")
	//cat.setName("kitty")
	//getAnimalName(cat)
}
