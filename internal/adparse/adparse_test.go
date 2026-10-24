package adparse_test

import (
	"reflect"
	"testing"

	"layzmd/internal/adparse"
)

// ---------------------------------------------------------------------------
// ParseKeyValues
// ---------------------------------------------------------------------------

func TestParseKeyValues(t *testing.T) {
	t.Run("basic two keys", func(t *testing.T) {
		text := "DNS Domain Name : corp.acme.com\nRealm : ACME.COM"
		got := adparse.ParseKeyValues(text)
		want := map[string][]string{
			"dns domain name": {"corp.acme.com"},
			"realm":           {"ACME.COM"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("duplicate keys accumulate", func(t *testing.T) {
		text := "DNS Domain Name : corp.acme.com\nDNS Domain Name : acme.com"
		got := adparse.ParseKeyValues(text)
		if len(got["dns domain name"]) != 2 {
			t.Errorf("expected 2 values for duplicate key, got %v", got)
		}
	})

	t.Run("empty text returns empty map", func(t *testing.T) {
		got := adparse.ParseKeyValues("")
		if len(got) != 0 {
			t.Errorf("expected empty map, got %v", got)
		}
	})

	t.Run("keys are lowercased", func(t *testing.T) {
		text := "NetBIOS Domain Name : CORP"
		got := adparse.ParseKeyValues(text)
		if _, ok := got["netbios domain name"]; !ok {
			t.Errorf("expected lowercased key, got %v", got)
		}
	})

	t.Run("leading whitespace tolerated", func(t *testing.T) {
		text := "  DNS Tree Name : acme.com"
		got := adparse.ParseKeyValues(text)
		if got["dns tree name"] == nil {
			t.Errorf("expected key with leading whitespace, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// ParseNetbiosAssignments
// ---------------------------------------------------------------------------

func TestParseNetbiosAssignments(t *testing.T) {
	t.Run("two assignments", func(t *testing.T) {
		text := "DC01 = Domain Controllers\nWS01 = Workstations"
		got := adparse.ParseNetbiosAssignments(text)
		want := [][2]string{
			{"DC01", "Domain Controllers"},
			{"WS01", "Workstations"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("empty text returns nil", func(t *testing.T) {
		got := adparse.ParseNetbiosAssignments("")
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("non-matching lines skipped", func(t *testing.T) {
		text := "some random line without equals\nDC01 = Domain Controllers"
		got := adparse.ParseNetbiosAssignments(text)
		if len(got) != 1 {
			t.Errorf("expected 1 match, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// ParseFqdnResolution
// ---------------------------------------------------------------------------

func TestParseFqdnResolution(t *testing.T) {
	t.Run("standard resolves as", func(t *testing.T) {
		got := adparse.ParseFqdnResolution("10.0.0.5 resolves as dc01.corp.acme.com.")
		if got != "dc01.corp.acme.com" {
			t.Errorf("got %q, want %q", got, "dc01.corp.acme.com")
		}
	})

	t.Run("trailing dot stripped", func(t *testing.T) {
		got := adparse.ParseFqdnResolution("1.2.3.4 resolves as host.example.com.")
		if got != "host.example.com" {
			t.Errorf("got %q, want %q", got, "host.example.com")
		}
	})

	t.Run("no match returns empty", func(t *testing.T) {
		got := adparse.ParseFqdnResolution("nothing to see here")
		if got != "" {
			t.Errorf("got %q, want %q", got, "")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		got := adparse.ParseFqdnResolution("10.0.0.1 Resolves As host.corp.com.")
		if got != "host.corp.com" {
			t.Errorf("got %q, want %q", got, "host.corp.com")
		}
	})
}

// ---------------------------------------------------------------------------
// ParseDNDomains
// ---------------------------------------------------------------------------

func TestParseDNDomains(t *testing.T) {
	t.Run("basic dc= chain", func(t *testing.T) {
		got := adparse.ParseDNDomains("Base DN: dc=corp,dc=acme,dc=com")
		want := []string{"corp.acme.com"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("no dc= returns nil", func(t *testing.T) {
		got := adparse.ParseDNDomains("some other text without dc equals")
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("full LDAP DN", func(t *testing.T) {
		got := adparse.ParseDNDomains("CN=Users,dc=corp,dc=acme,dc=com")
		if len(got) == 0 || got[0] != "corp.acme.com" {
			t.Errorf("got %v, want [corp.acme.com]", got)
		}
	})

	t.Run("case insensitive DC=", func(t *testing.T) {
		got := adparse.ParseDNDomains("DC=corp,DC=example,DC=com")
		if len(got) == 0 || got[0] != "corp.example.com" {
			t.Errorf("got %v, want [corp.example.com]", got)
		}
	})
}

// ---------------------------------------------------------------------------
// DomainFromComponents
// ---------------------------------------------------------------------------

func TestDomainFromComponents(t *testing.T) {
	t.Run("basic join", func(t *testing.T) {
		got := adparse.DomainFromComponents([]string{"corp", "acme", "com"})
		if got != "corp.acme.com" {
			t.Errorf("got %q, want %q", got, "corp.acme.com")
		}
	})

	t.Run("empty components returns empty", func(t *testing.T) {
		got := adparse.DomainFromComponents([]string{})
		if got != "" {
			t.Errorf("got %q, want %q", got, "")
		}
	})

	t.Run("single component no dot returns empty", func(t *testing.T) {
		got := adparse.DomainFromComponents([]string{"corp"})
		// no dot → normalize_domain returns "" (no "." in domain)
		if got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})

	t.Run("TLD-first components reversed", func(t *testing.T) {
		// when first label is TLD-like (com, net, org, etc.) and len>1, reverse
		got := adparse.DomainFromComponents([]string{"com", "acme", "corp"})
		// reversed → "corp.acme.com"
		if got != "corp.acme.com" {
			t.Errorf("got %q, want %q", got, "corp.acme.com")
		}
	})
}

// ---------------------------------------------------------------------------
// ParseCertNames
// ---------------------------------------------------------------------------

func TestParseCertNames(t *testing.T) {
	t.Run("subject and issuer common names", func(t *testing.T) {
		text := "Subject:\n  Common Name: dc01.corp.acme.com\nIssuer:\n  Common Name: corp-CA"
		subjects, issuers := adparse.ParseCertNames(text)
		if !reflect.DeepEqual(subjects, []string{"dc01.corp.acme.com"}) {
			t.Errorf("subjects: got %v, want [dc01.corp.acme.com]", subjects)
		}
		if !reflect.DeepEqual(issuers, []string{"corp-CA"}) {
			t.Errorf("issuers: got %v, want [corp-CA]", issuers)
		}
	})

	t.Run("Subject Name and Issuer Name headers (Nessus format)", func(t *testing.T) {
		text := "Subject Name:\n  Common Name: host.example.com\nIssuer Name:\n  Common Name: Example-CA"
		subjects, issuers := adparse.ParseCertNames(text)
		if !reflect.DeepEqual(subjects, []string{"host.example.com"}) {
			t.Errorf("subjects: got %v, want [host.example.com]", subjects)
		}
		if !reflect.DeepEqual(issuers, []string{"Example-CA"}) {
			t.Errorf("issuers: got %v, want [Example-CA]", issuers)
		}
	})

	t.Run("empty text returns empty slices", func(t *testing.T) {
		subjects, issuers := adparse.ParseCertNames("")
		if len(subjects) != 0 || len(issuers) != 0 {
			t.Errorf("expected empty, got subjects=%v issuers=%v", subjects, issuers)
		}
	})

	t.Run("no matching sections returns empty", func(t *testing.T) {
		subjects, issuers := adparse.ParseCertNames("Some random text without cert sections")
		if len(subjects) != 0 || len(issuers) != 0 {
			t.Errorf("expected empty, got subjects=%v issuers=%v", subjects, issuers)
		}
	})
}

// ---------------------------------------------------------------------------
// RowSearchBlob
// ---------------------------------------------------------------------------

func TestRowSearchBlob(t *testing.T) {
	t.Run("joins and lowercases", func(t *testing.T) {
		got := adparse.RowSearchBlob("My Plugin", "Synopsis text", "Description here", "Output data")
		// all lowercased, space-joined
		want := "my plugin synopsis text description here output data"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("empty fields omitted", func(t *testing.T) {
		got := adparse.RowSearchBlob("Plugin", "", "Description", "")
		want := "plugin description"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("all empty returns empty", func(t *testing.T) {
		got := adparse.RowSearchBlob("", "", "", "")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// ---------------------------------------------------------------------------
// ContainsAnyBounded
// ---------------------------------------------------------------------------

func TestContainsAnyBounded(t *testing.T) {
	t.Run("phrase match", func(t *testing.T) {
		if !adparse.ContainsAnyBounded("has null session enabled", "null session") {
			t.Error("expected true for 'null session' in 'has null session enabled'")
		}
	})

	t.Run("word boundary prevents partial match", func(t *testing.T) {
		if adparse.ContainsAnyBounded("classes", "cla") {
			t.Error("expected false: 'cla' should not match in 'classes' at word boundary")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		if !adparse.ContainsAnyBounded("NULL SESSION detected", "null session") {
			t.Error("expected true for case-insensitive match")
		}
	})

	t.Run("exact word match", func(t *testing.T) {
		if !adparse.ContainsAnyBounded("smbv1 is enabled", "smbv1") {
			t.Error("expected true for smbv1")
		}
	})

	t.Run("no match returns false", func(t *testing.T) {
		if adparse.ContainsAnyBounded("nothing here", "smbv1", "null session") {
			t.Error("expected false")
		}
	})

	t.Run("empty needle skipped", func(t *testing.T) {
		if adparse.ContainsAnyBounded("anything", "") {
			t.Error("expected false for empty needle")
		}
	})

	t.Run("multiple needles first match wins", func(t *testing.T) {
		if !adparse.ContainsAnyBounded("adfs enabled on this server", "adfs", "federation") {
			t.Error("expected true for adfs")
		}
	})

	t.Run("non-alnum boundary: non-alnum start needle", func(t *testing.T) {
		// needle starting with non-alnum: no leading boundary check (per nadda.py)
		if !adparse.ContainsAnyBounded("user@domain.com is present", "@domain") {
			t.Error("expected true for @domain (non-alnum start)")
		}
	})
}

// ---------------------------------------------------------------------------
// NormalizeDomain
// ---------------------------------------------------------------------------

func TestNormalizeDomain(t *testing.T) {
	t.Run("trim spaces, lowercase, strip trailing dot", func(t *testing.T) {
		got := adparse.NormalizeDomain(" CORP.ACME.COM. ")
		if got != "corp.acme.com" {
			t.Errorf("got %q, want %q", got, "corp.acme.com")
		}
	})

	t.Run("already clean", func(t *testing.T) {
		got := adparse.NormalizeDomain("corp.acme.com")
		if got != "corp.acme.com" {
			t.Errorf("got %q, want %q", got, "corp.acme.com")
		}
	})

	t.Run("empty returns empty", func(t *testing.T) {
		got := adparse.NormalizeDomain("")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("trailing dot stripped", func(t *testing.T) {
		got := adparse.NormalizeDomain("example.com.")
		if got != "example.com" {
			t.Errorf("got %q, want %q", got, "example.com")
		}
	})
}

// ---------------------------------------------------------------------------
// NormalizeNetbiosDomain
// ---------------------------------------------------------------------------

func TestNormalizeNetbiosDomain(t *testing.T) {
	t.Run("trim and uppercase", func(t *testing.T) {
		got := adparse.NormalizeNetbiosDomain(" corp ")
		if got != "CORP" {
			t.Errorf("got %q, want %q", got, "CORP")
		}
	})

	t.Run("already uppercase", func(t *testing.T) {
		got := adparse.NormalizeNetbiosDomain("ACME")
		if got != "ACME" {
			t.Errorf("got %q, want %q", got, "ACME")
		}
	})

	t.Run("lowercase input", func(t *testing.T) {
		got := adparse.NormalizeNetbiosDomain("  domain  ")
		if got != "DOMAIN" {
			t.Errorf("got %q, want %q", got, "DOMAIN")
		}
	})
}

// ---------------------------------------------------------------------------
// DomainFromFqdn
// ---------------------------------------------------------------------------

func TestDomainFromFqdn(t *testing.T) {
	t.Run("four part fqdn", func(t *testing.T) {
		got := adparse.DomainFromFqdn("dc01.corp.acme.com")
		if got != "corp.acme.com" {
			t.Errorf("got %q, want %q", got, "corp.acme.com")
		}
	})

	t.Run("three part fqdn", func(t *testing.T) {
		got := adparse.DomainFromFqdn("host.example.com")
		if got != "example.com" {
			t.Errorf("got %q, want %q", got, "example.com")
		}
	})

	t.Run("only hostname no domain", func(t *testing.T) {
		got := adparse.DomainFromFqdn("hostname")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("empty returns empty", func(t *testing.T) {
		got := adparse.DomainFromFqdn("")
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}
