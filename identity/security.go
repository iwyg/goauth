package identity

type IdentityChecker interface {
	CheckPreAuth(Identity) error
	CheckPostAuth(Identity) error
}

type checkerImpl struct {
}

func (c *checkerImpl) CheckPreAuth(id Identity) error {
	return nil
}

func (c *checkerImpl) CheckPostAuth(id Identity) error {
	return nil
}

func NewBaseIdentityChecker() IdentityChecker {
	return &checkerImpl{}
}
