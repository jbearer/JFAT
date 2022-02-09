CC_FLAGS = -Wall -Wextra -Werror -g3 -Og

FUSE_FLAGS = `pkg-config fuse --cflags --libs`

TORTURE_FLAGS =

ifdef VALGRIND
	TORTURE_FLAGS += --valgrind
endif

ifdef PROFILE
	CC_FLAGS += -pg
endif

all: jfat sh_pwrite

clean:
	rm -f jfat
	rm -f sh_pwrite
	rm -rf docs
	rm -f *.log
	rm -f *.prof
	rm -f *.dot
	rm -f *.png

torture: jfat sh_pwrite jfat_torture.sh
	./jfat_torture.sh $(TORTURE_FLAGS)

jfat: jfat.c
	$(CC) -o jfat $(CC_FLAGS) jfat.c $(FUSE_FLAGS)

sh_pwrite: sh_pwrite.c
	$(CC) -o sh_pwrite $(CC_FLAGS) sh_pwrite.c

docs: jfat.c doxygen.config
	mkdir -p docs
	doxygen doxygen.config

ifdef PROFILE
%.prof: %.sh jfat
	bash $<
	gprof jfat > $@

%.dot: %.prof
	gprof2dot $< > $@

%.png: %.dot
	dot $< -Tpng -o $@

endif
