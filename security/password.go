package security

import (
	"golang.org/x/crypto/bcrypt"
)

type PasswordEncoder interface {
	EncodePass(plain []byte) ([]byte, error)
}

type PasswordChecker interface {
	CheckPass(plain []byte, hash []byte) error
}

type BCryptPasswordEncoder struct {
	Cost int
}

func (enc *BCryptPasswordEncoder) EncodePass(plain []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(plain, enc.Cost)
}

type BCryptPasswordChecker struct{}

func (ck *BCryptPasswordChecker) CheckPass(plain []byte, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, plain)
}

func NewBCryptPasswordChecker() *BCryptPasswordChecker {
	return &BCryptPasswordChecker{}
}

func NewBCryptPasswordEncoder(cost int) *BCryptPasswordEncoder {
	return &BCryptPasswordEncoder{Cost: bcrypt.DefaultCost}
}
