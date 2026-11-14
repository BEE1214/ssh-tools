VERSION  := $(shell cat .version 2>/dev/null || echo dev)
BINARY   := sshm
LDFLAGS  := -s -w -X github.com/adamdvorsky/ssh-tools/internal/cli.version=$(VERSION)
GOFLAGS  := -trimpath
DESTDIR  ?=
PREFIX   ?= /usr/local

.PHONY: build test vet clean install uninstall completions arch rpm

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sshm/

test:
	go test ./internal/...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

install: build
	install -Dm755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	install -d $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	./$(BINARY) completion bash > $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(BINARY)
	./$(BINARY) completion zsh  > $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(BINARY)
	./$(BINARY) completion fish > $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(BINARY).fish

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(BINARY).fish

completions: build
	./$(BINARY) completion bash > packaging/completions/sshm.bash
	./$(BINARY) completion zsh  > packaging/completions/_sshm
	./$(BINARY) completion fish > packaging/completions/sshm.fish

# Build Arch Linux package from local git checkout
arch:
	cd packaging/arch && cp -f PKGBUILD-git PKGBUILD && makepkg -f

# Build RPM using rpmbuild (requires rpmdevtools)
rpm:
	mkdir -p ~/rpmbuild/{SOURCES,SPECS}
	tar --transform 's,^\.,ssh-tools-$(VERSION),' -czf ~/rpmbuild/SOURCES/sshm-$(VERSION).tar.gz .
	cp packaging/rpm/sshm.spec ~/rpmbuild/SPECS/
	rpmbuild -ba ~/rpmbuild/SPECS/sshm.spec