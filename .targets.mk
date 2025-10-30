# draft-ietf-lamps-pq-composite-kem
# draft-ietf-lamps-pq-composite-kem-03 draft-ietf-lamps-pq-composite-kem-04 draft-ietf-lamps-pq-composite-kem-05 draft-ietf-lamps-pq-composite-kem-06 draft-ietf-lamps-pq-composite-kem-07 draft-ietf-lamps-pq-composite-kem-08
versioned:
	@mkdir -p $@
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-03.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-03.xml
versioned/draft-ietf-lamps-pq-composite-kem-03.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-03:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-pq-composite-kem-date/2024-03-02/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-03/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-03\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-03\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-03/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-04.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-04.xml
versioned/draft-ietf-lamps-pq-composite-kem-04.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-04:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-pq-composite-kem-date/2024-07-08/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-04/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-04\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-04\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-04/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-05.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-05.xml
versioned/draft-ietf-lamps-pq-composite-kem-05.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-05:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-pq-composite-kem-date/2024-10-21/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-05/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-05\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-05\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-05/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-06.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-06.xml
versioned/draft-ietf-lamps-pq-composite-kem-06.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-06:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-pq-composite-kem-date/2025-03-04/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-06/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-06\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-06\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-06/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-07.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-07.xml
versioned/draft-ietf-lamps-pq-composite-kem-07.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-07:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-cms-composite-kem-date/2025-10-29/g' -e 's/draft-ietf-lamps-cms-composite-kem-latest/draft-ietf-lamps-cms-composite-kem-00/g' -e 's/draft-ietf-lamps-pq-composite-kem-date/2025-06-16/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-07/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-07\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-07\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-07/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-08.md
.SECONDARY: versioned/draft-ietf-lamps-pq-composite-kem-08.xml
versioned/draft-ietf-lamps-pq-composite-kem-08.md: | versioned
	git show "draft-ietf-lamps-pq-composite-kem-08:draft-ietf-lamps-pq-composite-kem.md" | sed -e 's/draft-ietf-lamps-cms-composite-kem-date/2025-10-29/g' -e 's/draft-ietf-lamps-cms-composite-kem-latest/draft-ietf-lamps-cms-composite-kem-00/g' -e 's/draft-ietf-lamps-pq-composite-kem-date/2025-10-16/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-08/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-08\//; }' >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-08\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-08/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=$$(mktemp -d); git clone . -b "$$tag" "$$tmp"; \
	     ln -s "$(LIBDIR)" "$$tmp/$(LIBDIR)"; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	     rm -rf "$$tmp"; \
	  ); \
	done
.INTERMEDIATE: versioned/draft-ietf-lamps-pq-composite-kem-09.md
versioned/draft-ietf-lamps-pq-composite-kem-09.md: draft-ietf-lamps-pq-composite-kem.md | versioned
	sed -e 's/draft-ietf-lamps-cms-composite-kem-date/2025-10-29/g' -e 's/draft-ietf-lamps-cms-composite-kem-latest/draft-ietf-lamps-cms-composite-kem-00/g' -e 's/draft-ietf-lamps-pq-composite-kem-date/2025-10-29/g' -e 's/draft-ietf-lamps-pq-composite-kem-latest/draft-ietf-lamps-pq-composite-kem-09/g' -e '/^{::include [^\/]/{ s/^{::include /{::include draft-ietf-lamps-pq-composite-kem-09\//; }' $< >$@
	for inc in $$(sed -ne '/^{::include [^\/]/{ s/^{::include draft-ietf-lamps-pq-composite-kem-09\///;s/}$$//; p; }' $@); do \
	  target=draft-ietf-lamps-pq-composite-kem-09/$$inc; \
	  mkdir -p $$(dirname "$$target"); \
	  git show "$$tag:$$inc" >"$$target" || \
	    (echo "Attempting to make a copy of $$inc"; \
	     tmp=.; \
	     make -C "$$tmp" "$$inc" && cp "$$tmp/$$inc" "$$target"; \
	  ); \
	done
diff-draft-ietf-lamps-pq-composite-kem.html: versioned/draft-ietf-lamps-pq-composite-kem-08.txt versioned/draft-ietf-lamps-pq-composite-kem-09.txt
	-$(iddiff) $^ > $@
