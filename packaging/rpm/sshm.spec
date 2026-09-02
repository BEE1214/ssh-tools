Name:           sshm
Version:        0.1.0
Release:        1%{?dist}
Summary:        SSH config manager — TUI and CLI tool for managing ~/.ssh/config

License:        GPL-2.0-only
URL:            https://github.com/BEE1214/ssh-tools
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  make

# RHEL/Rocky 8: Go from EPEL or AppStream (golang >= 1.21)
# RHEL/Rocky 9/10: Go in base repos (golang >= 1.21)
%if 0%{?rhel} == 8
BuildRequires:  go-toolset
%endif

%if 0%{?rhel} >= 9
BuildRequires:  golang >= 1.21
%endif

# No runtime dependencies — static Go binary
Requires:       openssh-clients
Suggests:       bash-completion

%description
sshm is a TUI and CLI tool for managing ~/.ssh/config hosts. It reads and
writes your SSH config directly — no database, no shadow state, no separate
format. Features include fuzzy host search, shell completion, config
validation, short-lived SSH certificate management, and atomic writes with
automatic backup.

%prep
%autosetup -n ssh-tools-%{version}

%build
export CGO_ENABLED=0
export GOCACHE=%{_builddir}/go-cache
export GOMODCACHE=%{_builddir}/go-mod

go build \
    -trimpath \
    -ldflags "-s -w -X github.com/adamdvorsky/ssh-tools/internal/cli.version=%{version}" \
    -o sshm \
    ./cmd/sshm/

%check
go test ./internal/... || true

%install
# Binary
install -Dpm 0755 sshm %{buildroot}%{_bindir}/sshm

# Shell completions
./sshm completion bash > sshm.bash
./sshm completion zsh > _sshm
./sshm completion fish > sshm.fish

install -Dpm 0644 sshm.bash %{buildroot}%{_datadir}/bash-completion/completions/sshm
install -Dpm 0644 _sshm     %{buildroot}%{_datadir}/zsh/site-functions/_sshm
install -Dpm 0644 sshm.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/sshm.fish

# License
install -Dpm 0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license LICENSE
%{_bindir}/sshm
%{_datadir}/bash-completion/completions/sshm
%{_datadir}/zsh/site-functions/_sshm
%{_datadir}/fish/vendor_completions.d/sshm.fish
%{_licensedir}/%{name}/LICENSE

%changelog
* Mon Sep 02 2026 Adam Dvorsky <advorsky.gos@gmail.com> - 0.1.0-1
- Initial package
- CLI and TUI SSH config manager with certificate support