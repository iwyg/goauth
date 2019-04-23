package role

type Role string

func (r *Role) String() string {
	return string(*r)
}

const (
	RLAnon    Role = "ROLE_ANON"
	RLAdmin   Role = "ROLE_ADMIN"
	RLUser    Role = "ROLE_USER"
	RLDefault      = RLAnon
)
