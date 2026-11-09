package collect

import "testing"

func TestConnTemplate(t *testing.T) {
	cases := map[string]string{
		"mongodb://dba:secret@172.21.0.2:27017/?authSource=admin":                             "mongodb://dba:****@{host}/?authSource=admin",
		"mongodb://u:p@h1:27017,h2:27017/admin?replicaSet=rs0&tls=true&tlsCAFile=/etc/ca.pem": "mongodb://u:****@{host}/admin?tls=true&tlsCAFile=/etc/ca.pem",
		"mongodb://127.0.0.1:28300/?replicaSet=rs90":                                          "mongodb://{host}/",
		"mongodb+srv://app:pw@cluster.example.net/?authSource=admin":                          "mongodb://app:****@{host}/?authSource=admin&tls=true",
		"mongodb://onlyuser@h:27017":                                                          "mongodb://onlyuser@{host}/",
		"http://nope":                                                                         "",
	}
	for in, want := range cases {
		if got := ConnTemplate(in); got != want {
			t.Errorf("ConnTemplate(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ConnTemplate("mongodb://u:s3cr3t@h/?authSource=admin"); containsSecret(got) {
		t.Errorf("password leaked: %q", got)
	}
}

func containsSecret(s string) bool {
	for i := 0; i+6 <= len(s); i++ {
		if s[i:i+6] == "s3cr3t" {
			return true
		}
	}
	return false
}
