package app

// App is the main app struct where all logic lays
type App struct {
	RootDirectory    string
	WorkingDirectory string

	CertificateInformation *certInfo
}
