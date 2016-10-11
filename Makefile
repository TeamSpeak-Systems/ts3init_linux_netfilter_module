all:
	$(MAKE) -C src;
	$(MAKE) -C src -f Makefile.xtables;
	$(MAKE) -C test;

clean:
	$(MAKE) -C src clean;
	$(MAKE) -C src -f Makefile.xtables clean;
	$(MAKE) -C test clean;

install:
	$(MAKE) -C src modules_install;
	$(MAKE) -C src -f Makefile.xtables install;

