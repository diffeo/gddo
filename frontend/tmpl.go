package main

import (
	"html/template"
)

var templates = template.Must(template.New("auth").Parse(authPage))

const authPage = `
<!DOCTYPE html>
<html lang="en">
<head>
	<title>Authenticate</title>
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
</head>
<body>
	<div class="container" align="center">
		<h1>Authenticate</h1>
		{{ if .JustFailed }}
		<div class="alert alert-warning" role="alert">{{ .FailureMessage }}</div>
		{{ end }}
		<p>To access this content, please login with your Rastech Software google account.</p>
		<form method="POST">
			<button type="submit" class="btn btn-default">Login</button>
		</form>
	</div>
</body>
</html>
`
