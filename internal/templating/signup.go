package templating

type SignupPage struct {
	Form FormData
}

func NewSignupPage() SignupPage {
	return SignupPage{
		Form: NewFormData(),
	}
}
