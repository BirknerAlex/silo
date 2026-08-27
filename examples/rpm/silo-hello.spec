# A minimal but genuinely valid RPM: it has a version, a release, an arch,
# a dependency, a file list and a changelog — which is the whole set of
# things repodata has to round-trip.
Name:           silo-hello
Version:        1.2.3
Release:        4
Summary:        A tiny package for silo's end-to-end tests
License:        MIT
URL:            https://github.com/BirknerAlex/silo
BuildArch:      noarch

# A real dependency, so primary.xml has a non-empty <rpm:requires> to
# round-trip and dnf has something to actually resolve.
Requires:       bash

%description
Prints a line. Exists so silo's end-to-end suite can publish a real RPM,
serve it through the repodata silo generates, and have real dnf resolve,
download, verify and install it.

%prep
# Nothing to unpack: the payload is written in %install.

%build
# Nothing to compile.

%install
mkdir -p %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/silo-hello <<'SCRIPT'
#!/bin/bash
echo "hello from silo rpm 1.2.3"
SCRIPT
chmod 0755 %{buildroot}%{_bindir}/silo-hello

mkdir -p %{buildroot}%{_datadir}/silo-hello
echo "not a primary file" > %{buildroot}%{_datadir}/silo-hello/README

%files
# /usr/bin/... lands in primary.xml, /usr/share/... only in filelists.xml.
# Having both means the suite can tell the two apart.
%{_bindir}/silo-hello
%{_datadir}/silo-hello/README

%changelog
* Mon Jan 01 2024 silo <silo@example.com> - 1.2.3-4
- A changelog entry, so other.xml has something to carry.
